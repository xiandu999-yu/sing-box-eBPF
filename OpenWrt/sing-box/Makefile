# sing-box (CHIZI-0618 eBPF fork + sing-ebpf 模块)
#
# 源码来自本仓库 sing-box-src release 里组装好的 tarball：
#   sing-box/src     ← sing-box（已打补丁）
#   sing-box/module  ← sing-ebpf（已打补丁，含预编译 .o）
# OpenWrt 侧不做模块拉取、不打补丁、不跑 clang。
#
# PKG_SOURCE / PKG_HASH 由 .github/workflows/assemble-source.yml 自动写回。

include $(TOPDIR)/rules.mk

PKG_NAME:=sing-box
PKG_VERSION:=1.15.0-alpha.13
PKG_RELEASE:=8

PKG_SOURCE:=sing-box-src-1.15.0-alpha.13-937036048974.tar.gz
PKG_SOURCE_URL:=https://github.com/xiandu999-yu/sing-box-eBPF/releases/download/sing-box-src/
PKG_HASH:=937036048974616c26d546689ce64084be59e10574ffd1da561bda95027a49cd

PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=xiandu999-yu
PKG_CPE_ID:=cpe:/a:sagernet:sing-box

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

# tarball 里是 sing-box/{src,module}，剥掉顶层后 src 就是模块根目录。
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/src
PKG_UNPACK:=$(HOST_TAR) -C $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION) --strip-components=1 -xzf $(DL_DIR)/$(PKG_SOURCE)

GO_PKG:=github.com/sagernet/sing-box
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/sing-box
GO_PKG_LDFLAGS:=-checklinkname=0 -s -w -buildid=
GO_PKG_LDFLAGS_X:=$(GO_PKG)/constant.Version=$(PKG_VERSION)
GO_PKG_TAGS:=with_ebpf,with_clash_api,with_quic,with_utls,with_gvisor,with_wireguard,badlinkname

include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

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
