include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-xlnetacc
PKG_VERSION:=1.0.5
PKG_RELEASE:=1

PKG_LICENSE:=GPLv2
PKG_MAINTAINER:=Sense <sensec@gmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=LuCI Support for XLNetAcc
	PKGARCH:=all
	DEPENDS:=+jshn +wget +openssl-util +luci-base
endef

define Package/$(PKG_NAME)/description
	LuCI Support for XLNetAcc.
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	killall -q xlnetacc.sh
	killall -q xlnetacc
	/etc/init.d/xlnetacc disable >/dev/null 2>&1 || true
	rm -f /tmp/xlnetacc_* /var/state/xlnetacc_*
fi
exit 0
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	if [ -f /etc/uci-defaults/luci-xlnetacc ]; then
		( . /etc/uci-defaults/luci-xlnetacc ) && rm -f /etc/uci-defaults/luci-xlnetacc
	fi
fi
exit 0
endef

define Package/$(PKG_NAME)/conffiles
	/etc/config/xlnetacc
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci
	cp -pR ./files/luci/* $(1)/usr/lib/lua/luci/

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(foreach po,$(wildcard $(CURDIR)/files/luci/i18n/*.po), \
		po2lmo $(po) $(1)/usr/lib/lua/luci/i18n/$(patsubst %.po,%.lmo,$(notdir $(po)));)
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/xlnetacc $(1)/etc/config/xlnetacc
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/xlnetacc $(1)/etc/init.d/xlnetacc
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/etc/hotplug.d/iface/95-xlnetacc $(1)/etc/hotplug.d/iface/95-xlnetacc
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/luci-xlnetacc $(1)/etc/uci-defaults/luci-xlnetacc
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/xlnetacc.sh $(1)/usr/bin/xlnetacc.sh
endef

$(eval $(call BuildPackage,$(PKG_NAME)))