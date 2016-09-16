plugindir = $(libdir)/NetworkManager

plugin_LTLIBRARIES = libnm-vpn-plugin-fortisslvpn.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-fortisslvpn-properties.la
endif

shared_sources = \
	$(top_srcdir)/shared/nm-service-defines.h \
	$(NULL)

plugin_sources = \
	nm-fortisslvpn-editor-plugin.c \
	nm-fortisslvpn-editor-plugin.h \
	nm-fortisslvpn-editor.c \
	nm-fortisslvpn-editor.h

uidir = $(datadir)/gnome-vpn-properties/fortisslvpn
ui_DATA = nm-fortisslvpn-dialog.ui

common_CFLAGS = \
	$(GLIB_CFLAGS) \
	"-I$(top_srcdir)/" \
	"-I$(top_srcdir)/shared/" \
	-DUIDIR=\""$(uidir)"\" \
	-DLOCALEDIR=\""$(datadir)/locale"\"

###############################################################################

libnm_vpn_plugin_fortisslvpn_la_SOURCES = \
	$(shared_sources) \
	$(plugin_sources)

libnm_vpn_plugin_fortisslvpn_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(common_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(NULL)

libnm_vpn_plugin_fortisslvpn_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

libnm_vpn_plugin_fortisslvpn_la_LDFLAGS = \
	-avoid-version

###############################################################################

libnm_fortisslvpn_properties_la_SOURCES = \
	$(shared_sources) \
	$(plugin_sources)

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
	-avoid-version

###############################################################################

CLEANFILES = *.bak *~

EXTRA_DIST = \
	$(ui_DATA)
