plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = 					\
	libnm-vpn-plugin-fortisslvpn.la			\
	libnm-fortisslvpn-properties.la

libnm_vpn_plugin_fortisslvpn_la_SOURCES =		\
	nm-fortisslvpn.c				\
	nm-fortisslvpn.h

libnm_fortisslvpn_properties_la_SOURCES =		\
	$(libnm_vpn_plugin_fortisslvpn_la_SOURCES)

uidir = $(datadir)/gnome-vpn-properties/fortisslvpn
ui_DATA = nm-fortisslvpn-dialog.ui

common_CFLAGS =						\
	$(GLIB_CFLAGS)					\
	$(GTK_CFLAGS)					\
	-I$(top_srcdir)					\
	-DUIDIR=\""$(uidir)"\"				\
	-DLOCALEDIR=\""$(datadir)/locale"\"		\
	-DG_DISABLE_DEPRECATED				\
	-DVERSION=\"$(VERSION)\"

libnm_vpn_plugin_fortisslvpn_la_CFLAGS =		\
	$(NM_CFLAGS)					\
	$(NMGTK_CFLAGS)					\
	$(common_CFLAGS)

libnm_fortisslvpn_properties_la_CFLAGS =		\
	-DNM_OPENVPN_OLD				\
	$(NM_CFLAGS)					\
	$(NMGTK_CFLAGS)					\
	$(common_CFLAGS)

libnm_vpn_plugin_fortisslvpn_la_LIBADD =		\
	$(GTK_LIBS)					\
	$(NM_LIBS)					\
	$(NMGTK_LIBS)

libnm_fortisslvpn_properties_la_LIBADD =		\
	$(GTK_LIBS)					\
	$(NM_LIBS)					\
	$(NMGTK_LIBS)

libnm_vpn_plugin_fortisslvpn_la_LDFLAGS =		\
	-avoid-version

libnm_fortisslvpn_properties_la_LDFLAGS =		\
	$(libnm_vpn_plugin_fortisslvpn_la_LDFLAGS)

CLEANFILES = *.bak *~

EXTRA_DIST =						\
	$(ui_DATA)
