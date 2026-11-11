// tcp-offload-probe：验证 TCP sockmap egress redirect 在我们的拓扑里是否可行。
//
// 只做机制验证，不改任何生产代码：
//
//	same  —— 四个 socket 都在 host netns（L/C 是“代理”两端，R/S 是“出口”两端）
//	cross —— L/C 在独立 netns（模拟 sing-box 的私有交付 netns），R/S 在 host
//
// 用法（路由器上 root）：
//
//	./tcp-offload-probe -mode both
//
// 每个场景的判定：
//
//	ping/pong 双向都通  → 该拓扑下 redirect 生效
//	ssock 命中 + redirect 返回 SK_PASS → cookie key 方案可用
package main

import (
	"bytes"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:embed objects/tcp_offload_probe_bpfel.o
var objects embed.FS

type probeKey struct {
	Cookie uint64
}

type env struct {
	name     string
	client   *net.TCPConn // 客户端侧：往代理写
	listener *net.TCPConn // 代理侧 accept（被重定向的接收端）
	outbound *net.TCPConn // 代理侧 dial（重定向的目标发送端）
	server   *net.TCPConn // 服务端侧 accept
}

func main() {
	var (
		mode    = flag.String("mode", "both", "same | cross | both")
		chunkMB = flag.Int("mb", 16, "throughput test size in MiB")
		child   = flag.String("child", "", "internal: run as netns child on this unix socket")
		keep    = flag.Bool("keep", false, "keep probe netns/veth after exit")
	)
	flag.Parse()

	if *child != "" {
		if err := runChild(*child); err != nil {
			fmt.Fprintln(os.Stderr, "child:", err)
			os.Exit(1)
		}
		return
	}

	exit := 0
	if *mode == "same" || *mode == "both" {
		if err := runSameNetns(*chunkMB); err != nil {
			fmt.Println("SAME-NETNS: FAIL:", err)
			exit = 1
		}
	}
	if *mode == "cross" || *mode == "both" {
		if err := runCrossNetns(*chunkMB, *keep); err != nil {
			fmt.Println("CROSS-NETNS: FAIL:", err)
			exit = 1
		}
	}
	os.Exit(exit)
}

// ---------- 场景搭建 ----------

func runSameNetns(chunkMB int) error {
	name := "same-netns"
	fmt.Println("=== " + name + " ===")

	serverListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer serverListener.Close()

	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer proxyListener.Close()

	// 客户端 → 代理监听
	client, err := net.Dial("tcp4", proxyListener.Addr().String())
	if err != nil {
		return err
	}
	defer client.Close()
	listener, err := proxyListener.Accept()
	if err != nil {
		return err
	}
	defer listener.Close()

	// 代理出站 → 服务端
	outbound, err := net.Dial("tcp4", serverListener.Addr().String())
	if err != nil {
		return err
	}
	defer outbound.Close()
	server, err := serverListener.Accept()
	if err != nil {
		return err
	}
	defer server.Close()

	e := &env{
		name:     name,
		client:   client.(*net.TCPConn),
		listener: listener.(*net.TCPConn),
		outbound: outbound.(*net.TCPConn),
		server:   server.(*net.TCPConn),
	}
	return runScenario(e, chunkMB)
}

func runCrossNetns(chunkMB int, keep bool) error {
	name := "cross-netns"
	fmt.Println("=== " + name + " ===")

	if _, err := exec.LookPath("ip"); err != nil {
		return errors.New("cross-netns 需要 iproute2 的 ip 命令")
	}
	nsName := "sbprobe"
	_ = exec.Command("ip", "netns", "del", nsName).Run()
	if out, err := exec.Command("ip", "netns", "add", nsName).CombinedOutput(); err != nil {
		return fmt.Errorf("ip netns add: %v (%s)", err, bytes.TrimSpace(out))
	}
	cleanup := func() {
		if !keep {
			_ = exec.Command("ip", "netns", "del", nsName).Run()
		}
	}
	defer cleanup()
	if out, err := exec.Command("ip", "-n", nsName, "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip -n %s link set lo up: %v (%s)", nsName, err, bytes.TrimSpace(out))
	}

	// 服务端在 host netns
	serverListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer serverListener.Close()

	// netns 里建 L/C
	lConn, cConn, stopChild, err := startChild(nsName)
	if err != nil {
		return err
	}
	defer stopChild()
	defer lConn.Close()
	defer cConn.Close()

	outbound, err := net.Dial("tcp4", serverListener.Addr().String())
	if err != nil {
		return err
	}
	defer outbound.Close()
	server, err := serverListener.Accept()
	if err != nil {
		return err
	}
	defer server.Close()

	e := &env{
		name:     name,
		client:   cConn,
		listener: lConn,
		outbound: outbound.(*net.TCPConn),
		server:   server.(*net.TCPConn),
	}
	return runScenario(e, chunkMB)
}

func startChild(nsName string) (*net.TCPConn, *net.TCPConn, func(), error) {
	self, err := os.Executable()
	if err != nil {
		return nil, nil, nil, err
	}
	dir, err := os.MkdirTemp("", "sbprobe")
	if err != nil {
		return nil, nil, nil, err
	}
	sockPath := filepath.Join(dir, "child.sock")
	unixListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return nil, nil, nil, err
	}

	cmd := exec.Command("ip", "netns", "exec", nsName, self, "-child", sockPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		unixListener.Close()
		return nil, nil, nil, err
	}
	stop := func() {
		unixListener.Close()
		_ = cmd.Wait()
		os.RemoveAll(dir)
	}

	_ = unixListener.SetDeadline(time.Now().Add(10 * time.Second))
	conn, err := unixListener.AcceptUnix()
	if err != nil {
		stop()
		return nil, nil, nil, fmt.Errorf("child 没连上来: %w", err)
	}
	fds, err := recvFDs(conn)
	conn.Close()
	if err != nil {
		stop()
		return nil, nil, nil, err
	}
	if len(fds) != 2 {
		stop()
		return nil, nil, nil, fmt.Errorf("child 给了 %d 个 fd", len(fds))
	}
	lConn, err := fileConn(fds[0])
	if err != nil {
		stop()
		return nil, nil, nil, err
	}
	cConn, err := fileConn(fds[1])
	if err != nil {
		stop()
		return nil, nil, nil, err
	}
	return lConn, cConn, stop, nil
}

func runChild(sockPath string) error {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		return err
	}
	accepted, err := listener.Accept()
	if err != nil {
		return err
	}
	listener.Close()

	lfd, err := fdOf(accepted.(*net.TCPConn))
	if err != nil {
		return err
	}
	cfd, err := fdOf(client.(*net.TCPConn))
	if err != nil {
		return err
	}
	if err := sendFDs(conn, []int{lfd, cfd}); err != nil {
		return err
	}
	// 保持两个 socket 存活直到父进程结束
	_, _ = io.Copy(io.Discard, conn)
	return nil
}

// ---------- 核心场景 ----------

func runScenario(e *env, chunkMB int) error {
	spec, err := loadSpec()
	if err != nil {
		return err
	}
	sockMap, err := ebpf.NewMap(spec.Maps["probe_sock"])
	if err != nil {
		return fmt.Errorf("create probe_sock: %w", err)
	}
	defer sockMap.Close()
	statsMap, err := ebpf.NewMap(spec.Maps["probe_stats"])
	if err != nil {
		return fmt.Errorf("create probe_stats: %w", err)
	}
	defer statsMap.Close()

	lfd, err := fdOf(e.listener)
	if err != nil {
		return err
	}
	rfd, err := fdOf(e.outbound)
	if err != nil {
		return err
	}

	useCookie := true
	prog, err := loadProgram(spec, "probe_verdict_cookie")
	if err != nil {
		fmt.Printf("cookie 程序加载失败: %v\n", err)
		fmt.Println("退回到 fixed-key 程序（只测单方向 redirect）")
		useCookie = false
		prog, err = loadProgram(spec, "probe_verdict_fixed")
		if err != nil {
			return fmt.Errorf("fixed 程序也加载失败: %w", err)
		}
	}
	defer prog.Close()

	if useCookie {
		lc, err := socketCookie(lfd)
		if err != nil {
			return fmt.Errorf("SO_COOKIE L: %w", err)
		}
		rc, err := socketCookie(rfd)
		if err != nil {
			return fmt.Errorf("SO_COOKIE R: %w", err)
		}
		fmt.Printf("cookies: L=%#x R=%#x\n", lc, rc)
		if err := sockMap.Update(&probeKey{Cookie: lc}, uint32(rfd), 0); err != nil {
			return fmt.Errorf("map L->R: %w", err)
		}
		if err := sockMap.Update(&probeKey{Cookie: rc}, uint32(lfd), 0); err != nil {
			return fmt.Errorf("map R->L: %w", err)
		}
	} else {
		if err := sockMap.Update(&probeKey{Cookie: 0}, uint32(rfd), 0); err != nil {
			return fmt.Errorf("map fixed->R: %w", err)
		}
	}

	lLink, err := attach(lfd, prog)
	if err != nil {
		return fmt.Errorf("attach L: %w", err)
	}
	defer lLink()
	if useCookie {
		rLink, err := attach(rfd, prog)
		if err != nil {
			return fmt.Errorf("attach R: %w", err)
		}
		defer rLink()
	}

	if err := e.ping(useCookie); err != nil {
		return err
	}
	if err := e.throughput(chunkMB, useCookie); err != nil {
		return err
	}
	dumpStats(statsMap)
	fmt.Printf("%s: PASS（cookie=%v）\n", e.name, useCookie)
	return nil
}

func (e *env) ping(bidirectional bool) error {
	deadline := time.Now().Add(5 * time.Second)
	_ = e.client.SetDeadline(deadline)
	_ = e.server.SetDeadline(deadline)

	payload := []byte("probe-ping-from-client")
	if _, err := e.client.Write(payload); err != nil {
		return fmt.Errorf("写 client: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(e.server, got); err != nil {
		return fmt.Errorf("服务端收不到（redirect 没生效 / 方向不对）: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("服务端收到脏数据: %q", got)
	}
	fmt.Println("client→server: ok")
	if !bidirectional {
		return nil
	}

	reverse := []byte("probe-pong-from-server")
	_ = e.server.SetWriteDeadline(deadline)
	if _, err := e.server.Write(reverse); err != nil {
		return fmt.Errorf("写 server: %w", err)
	}
	got = make([]byte, len(reverse))
	_ = e.client.SetDeadline(deadline)
	if _, err := io.ReadFull(e.client, got); err != nil {
		return fmt.Errorf("客户端收不到回程: %w", err)
	}
	if !bytes.Equal(got, reverse) {
		return fmt.Errorf("客户端收到脏数据: %q", got)
	}
	fmt.Println("server→client: ok")
	return nil
}

func (e *env) throughput(chunkMB int, bidirectional bool) error {
	if chunkMB <= 0 {
		return nil
	}
	total := int64(chunkMB) << 20
	chunk := make([]byte, 1<<20)
	deadline := time.Now().Add(2 * time.Minute)
	_ = e.client.SetDeadline(deadline)
	_ = e.server.SetDeadline(deadline)

	start := time.Now()
	errCh := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, e.server, total)
		errCh <- err
	}()
	var written int64
	for written < total {
		n := int64(len(chunk))
		if remaining := total - written; remaining < n {
			n = remaining
		}
		if _, err := e.client.Write(chunk[:n]); err != nil {
			return fmt.Errorf("吞吐写: %w（已写 %d）", err, written)
		}
		written += n
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("吞吐读: %w", err)
	}
	elapsed := time.Since(start)
	mbps := float64(total) * 8 / elapsed.Seconds() / 1e6
	fmt.Printf("throughput client→server: %.1f MiB in %s = %.1f Mbps（单向，%v）\n",
		float64(total)/(1<<20), elapsed.Round(time.Millisecond), mbps, bidirectional)
	return nil
}

// ---------- eBPF 小工具 ----------

func loadSpec() (*ebpf.CollectionSpec, error) {
	raw, err := objects.ReadFile("objects/tcp_offload_probe_bpfel.o")
	if err != nil {
		return nil, err
	}
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
}

func loadProgram(spec *ebpf.CollectionSpec, name string) (*ebpf.Program, error) {
	progSpec, ok := spec.Programs[name]
	if !ok {
		return nil, fmt.Errorf("程序 %s 不在对象里", name)
	}
	clone := progSpec.Copy()
	clone.Type = ebpf.SkSKB
	clone.AttachType = ebpf.AttachSkSKBStreamVerdict
	return ebpf.NewProgram(clone)
}

func attach(fd int, prog *ebpf.Program) (func(), error) {
	err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  fd,
		Program: prog,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		return nil, err
	}
	return func() {
		_ = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  fd,
			Program: prog,
			Attach:  ebpf.AttachSkSKBStreamVerdict,
		})
	}, nil
}

func fdOf(conn *net.TCPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	ctrlErr := raw.Control(func(value uintptr) { fd = int(value) })
	if ctrlErr != nil {
		return -1, ctrlErr
	}
	if fd < 0 {
		return -1, errors.New("拿不到 fd")
	}
	return fd, nil
}

func socketCookie(fd int) (uint64, error) {
	return unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
}

func dumpStats(stats *ebpf.Map) {
	labels := []string{"verdict_calls", "cookie_nonzero", "lookup_hit", "redirect_pass", "redirect_drop"}
	fmt.Print("kernel counters:")
	for index, label := range labels {
		var value uint64
		if err := stats.Lookup(uint32(index), &value); err != nil {
			fmt.Printf(" %s=?", label)
			continue
		}
		fmt.Printf(" %s=%d", label, value)
	}
	fmt.Println()
}

// ---------- fd 传递 ----------

func sendFDs(conn *net.UnixConn, fds []int) error {
	oob := unix.UnixRights(fds...)
	_, _, err := conn.WriteMsgUnix([]byte{'F'}, oob, nil)
	return err
}

func recvFDs(conn *net.UnixConn) ([]int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4*4))
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, err
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, message := range messages {
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			return nil, err
		}
		fds = append(fds, rights...)
	}
	return fds, nil
}

func fileConn(fd int) (*net.TCPConn, error) {
	file := os.NewFile(uintptr(fd), "probe-fd")
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, err
	}
	// net.FileConn 返回的是 dup 出来的副本，关掉原始 fd
	_ = unix.Close(fd)
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("fd %d 不是 TCP", fd)
	}
	return tcpConn, nil
}
