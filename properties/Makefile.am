plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-fortisslvpn-properties.la

libnm_fortisslvpn_properties_la_SOURCES =		\
	nm-fortisslvpn.c				\
	nm-fortisslvpn.h

uidir = $(datadir)/gnome-vpn-properties/fortisslvpn
ui_DATA = nm-fortisslvpn-dialog.ui

libnm_fortisslvpn_properties_la_CFLAGS =		\
	$(GLIB_CFLAGS)					\
	$(GTK_CFLAGS)					\
	$(NM_CFLAGS)					\
	$(NMGTK_CFLAGS)					\
	-I$(top_srcdir)					\
	-DUIDIR=\""$(uidir)"\"				\
	-DLOCALEDIR=\""$(datadir)/locale"\"		\
	-DG_DISABLE_DEPRECATED				\
	-DVERSION=\"$(VERSION)\"

libnm_fortisslvpn_properties_la_LIBADD =		\
	$(GTK_LIBS)					\
	$(NM_LIBS)					\
	$(NMGTK_LIBS)

libnm_fortisslvpn_properties_la_LDFLAGS =		\
	-avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =						\
	$(ui_DATA)
