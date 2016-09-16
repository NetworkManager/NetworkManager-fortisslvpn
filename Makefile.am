AUTOMAKE_OPTIONS = foreign

SUBDIRS = shared src properties

if WITH_GNOME
SUBDIRS += auth-dialog po
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-fortisslvpn-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-fortisslvpn-service.name

if WITH_LIBNM_GLIB
# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|@NM_PLUGIN_DIR@|g' \
	    <$(srcdir)/nm-fortisslvpn-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-fortisslvpn-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-fortisslvpn-service.name
endif

appdatadir = $(datadir)/appdata
appdata_DATA = $(appdata_in_files:.xml.in=.xml)
appdata_in_files = appdata/network-manager-fortisslvpn.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-fortisslvpn-service.name: $(srcdir)/nm-fortisslvpn-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $^ >$@

DISTCHECK_CONFIGURE_FLAGS = --enable-more-warnings=yes

EXTRA_DIST = \
	nm-fortisslvpn-service.name.in \
	$(dbusservice_DATA) \
	$(desktopfile) \
	$(iconfile) \
	$(appdata_in_files) \
	$(appdata_DATA) \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	contrib/README \
	contrib/fortiserve.pl \
	contrib/sslproxy.pl

CLEANFILES = \
	$(nmvpnservice_DATA) \
	$(desktop_DATA) \
	$(appdata_DATA)

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
