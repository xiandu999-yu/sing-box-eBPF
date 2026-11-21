# sing-box (CHIZI-0618 eBPF fork + sing-ebpf 模块)
#
# 源码来自本仓库 sing-box-src release 里组装好的 tarball，顶层只有 src：
#   sing-box/src            ← sing-box（补丁已打）
#   sing-box/src/module     ← sing-ebpf（补丁已打，.o 已生成）
#   go.mod: replace github.com/CHIZI-0618/sing-ebpf => ./module
#
# 所以这里【不要再放 patches/ 目录】——补丁在 CI 组装 tarball 时就打完了，
# OpenWrt 再打一次会 "No file to patch" / "previously applied"。
# 也不要在包目录里留 ./src，否则会被 OpenWrt 默认 Prepare 拷进 build_dir 干扰解包。
#
# PKG_SOURCE / PKG_HASH 由 .github/workflows/assemble-source.yml 自动写回。

include $(TOPDIR)/rules.mk

PKG_NAME:=sing-box
PKG_VERSION:=1.15.0-alpha.13
PKG_RELEASE:=1

PKG_SOURCE:=sing-box-src-1.15.0-alpha.13-6f6a73c6a729.tar.gz
PKG_SOURCE_URL:=https://github.com/xiandu999-yu/sing-box-eBPF/releases/download/sing-box-src/
PKG_HASH:=6f6a73c6a7295cfa480ccba92e790fcd00256e2e868ce319f59b6b7a7d47dfa5

PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=xiandu999-yu
PKG_CPE_ID:=cpe:/a:sagernet:sing-box

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

# tarball 顶层是 sing-box/src（新包）或 sing-box/{src,module}（旧包）。
# OpenWrt 的 golang-package 只把 PKG_BUILD_DIR（= .../src）拷进 GOPATH，
# 兄弟目录 ../module 在那边不存在，所以：
#   * 新 tarball：模块已经在 src/module，go.mod 是 replace => ./module；
#   * 旧 tarball：下面 Build/Prepare 会把 module 挪进 src 并改写 replace。
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/src

GO_PKG:=github.com/sagernet/sing-box
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/sing-box
GO_PKG_LDFLAGS:=-checklinkname=0 -s -w -buildid=
GO_PKG_LDFLAGS_X:=$(GO_PKG)/constant.Version=$(PKG_VERSION)
GO_PKG_TAGS:=with_ebpf,with_clash_api,with_quic,with_utls,with_gvisor,with_wireguard,badlinkname

# package.mk 必须先于 golang-package.mk：BuildPackage（以及 compile/clean 目标）
# 由 package.mk 定义，golang-package.mk 只提供 GO_PKG 那套钩子。
# 缺了它，$(eval $(call BuildPackage,sing-box)) 就是空操作，make 会报
# "No rule to make target 'compile'"。
include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

# 必须放在 package.mk 之后：package.mk 末尾有 `Build/Prepare=$(call Build/Prepare/Default,)`，
# 放在它前面会被覆盖回默认解包（<TAR> -C $(PKG_BUILD_DIR)，布局不对）。
define Build/Prepare
	rm -rf $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
	mkdir -p $(PKG_BUILD_DIR)
	tar -C $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION) --strip-components=1 -xzf $(DL_DIR)/$(PKG_SOURCE)
	if [ -d $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/module ]; then \
		mv $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/module $(PKG_BUILD_DIR)/module; \
		sed -i 's#=> \.\./module#=> ./module#' $(PKG_BUILD_DIR)/go.mod; \
	fi
endef

define Package/sing-box
  SECTION:=net
  CATEGORY:=Network
  TITLE:=The universal proxy platform (eBPF build)
  URL:=https://github.com/CHIZI-0618/sing-box
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle +kmod-inet-diag +kmod-tun
  USERID:=sing-box=5566:sing-box=5566
endef

define Package/sing-box/description
  sing-box with the eBPF inbound (CHIZI-0618 fork), assembled and patched in
  sing-box-eBPF. Ships local/shared data planes, TCX ordering and delivery link.
endef

define Package/sing-box/conffiles
/etc/config/sing-box
/etc/sing-box/
endef

define Package/sing-box/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/sing-box $(1)/usr/bin/sing-box

	$(INSTALL_DIR) $(1)/etc/sing-box
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/release/config/config.json $(1)/etc/sing-box

	$(INSTALL_DIR) $(1)/etc/config/
	$(INSTALL_CONF) ./files/sing-box.conf $(1)/etc/config/sing-box
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/sing-box.init $(1)/etc/init.d/sing-box
endef

$(eval $(call BuildPackage,sing-box))
