plugindir = $(libdir)/NetworkManager

plugin_LTLIBRARIES = libnm-vpn-plugin-fortisslvpn.la
if WITH_GNOME
plugin_LTLIBRARIES += libnm-vpn-plugin-fortisslvpn-editor.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-fortisslvpn-properties.la
endif
endif

shared_sources = \
	$(top_srcdir)/shared/nm-service-defines.h \
	$(NULL)

plugin_sources = \
	nm-fortisslvpn-editor-plugin.c \
	nm-fortisslvpn-editor-plugin.h

editor_sources = \
	nm-fortisslvpn-editor.c \
	nm-fortisslvpn-editor.h

uidir = $(datadir)/gnome-vpn-properties/fortisslvpn
if WITH_GNOME
ui_DATA = nm-fortisslvpn-dialog.ui
endif

common_CFLAGS = \
	$(GLIB_CFLAGS) \
	"-I$(top_srcdir)/" \
	"-I$(top_srcdir)/shared/" \
	-DUIDIR=\""$(uidir)"\" \
	-DLOCALEDIR=\""$(datadir)/locale"\"

###############################################################################

libnm_vpn_plugin_fortisslvpn_la_SOURCES = \
	$(shared_sources) \
	$(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.c \
	$(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.h \
	$(plugin_sources)

libnm_vpn_plugin_fortisslvpn_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(NULL)

libnm_vpn_plugin_fortisslvpn_la_LIBADD = \
	$(LIBNM_LIBS) \
	$(DL_LIBS) \
	$(NULL)

libnm_vpn_plugin_fortisslvpn_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/libnm-vpn-plugin-fortisslvpn.ver

###############################################################################

libnm_vpn_plugin_fortisslvpn_editor_la_SOURCES = \
	$(shared_sources) \
	$(editor_sources)

libnm_vpn_plugin_fortisslvpn_editor_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(common_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(NULL)

libnm_vpn_plugin_fortisslvpn_editor_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

libnm_vpn_plugin_fortisslvpn_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/libnm-vpn-plugin-fortisslvpn-editor.ver

###############################################################################

libnm_fortisslvpn_properties_la_SOURCES = \
	$(shared_sources) \
	$(plugin_sources) \
	$(editor_sources)

libnm_fortisslvpn_properties_la_CFLAGS = \
	-DNM_VPN_OLD \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(common_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS) \
	$(NULL)

libnm_fortisslvpn_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS)

libnm_fortisslvpn_properties_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/libnm-fortisslvpn-properties.ver

###############################################################################

CLEANFILES = *.bak *~

EXTRA_DIST = \
	libnm-vpn-plugin-fortisslvpn.ver \
	libnm-vpn-plugin-fortisslvpn-editor.ver \
	libnm-fortisslvpn-properties.ver \
	nm-fortisslvpn-dialog.ui
