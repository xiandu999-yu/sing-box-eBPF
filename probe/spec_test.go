package main

import (
	"testing"

	"github.com/cilium/ebpf"
)

// 只做 ELF/BTF 解析，不需要 root，用来保证提交的对象和程序名一致。
func TestProbeObjectLayout(t *testing.T) {
	spec, err := loadSpec()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	for _, name := range []string{"probe_sock", "probe_stats"} {
		if _, ok := spec.Maps[name]; !ok {
			t.Fatalf("map %s missing", name)
		}
	}
	sockMap, ok := spec.Maps["probe_sock"]
	if !ok {
		t.Fatal("probe_sock missing")
	}
	if sockMap.Type != ebpf.SockHash {
		t.Fatalf("probe_sock type = %v, want SockHash", sockMap.Type)
	}
	if sockMap.KeySize != 8 {
		t.Fatalf("probe_sock key size = %d, want 8", sockMap.KeySize)
	}
	if sockMap.ValueSize != 4 {
		t.Fatalf("probe_sock value size = %d, want 4 (u32 fd)", sockMap.ValueSize)
	}
	for _, name := range []string{"probe_verdict_cookie", "probe_verdict_fixed"} {
		prog, ok := spec.Programs[name]
		if !ok {
			t.Fatalf("program %s missing", name)
		}
		if prog.Type != ebpf.SkSKB {
			t.Fatalf("%s type = %v, want SkSKB", name, prog.Type)
		}
	}
}
