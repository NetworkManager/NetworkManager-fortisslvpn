fortisslvpn_statedir = $(sharedstatedir)/$(PACKAGE)

install-data-hook:
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(fortisslvpn_statedir)

AM_CPPFLAGS =							\
	$(DBUS_GLIB_CFLAGS)					\
	$(GLIB_CFLAGS)						\
	$(NM_CFLAGS)						\
	-I$(top_srcdir)						\
	-DG_DISABLE_DEPRECATED					\
	-DNM_FORTISSLVPN_LOCALEDIR=\"$(datadir)/locale\"	\
	-DNM_FORTISSLVPN_STATEDIR=\"$(fortisslvpn_statedir)\"	\
	-DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\" 

libexec_PROGRAMS = nm-fortisslvpn-service

nm_fortisslvpn_service_SOURCES =				\
	nm-fortisslvpn-service.c				\
	nm-fortisslvpn-service.h

nm-fortisslvpn-pppd-service-glue.h: $(top_srcdir)/src/nm-fortisslvpn-pppd-service.xml
	dbus-binding-tool --prefix=nm_fortisslvpn_pppd_service --mode=glib-server --output=$@ $<

nm_fortisslvpn_service_LDADD =					\
	$(DBUS_GLIB_LIBS)					\
	$(GLIB_LIBS)						\
	$(NM_LIBS)

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-fortisslvpn-pppd-plugin.la

nm_fortisslvpn_pppd_plugin_la_SOURCES =				\
	nm-fortisslvpn-pppd-plugin.c				\
	nm-ppp-status.h

nm_fortisslvpn_pppd_plugin_la_CPPFLAGS =			\
	$(DBUS_GLIB_CFLAGS)					\
	$(GLIB_CFLAGS)						\
	$(NM_CFLAGS)

nm_fortisslvpn_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_fortisslvpn_pppd_plugin_la_LIBADD =				\
	$(DBUS_GLIB_LIBS)					\
	$(GLIB_LIBS)						\
	$(NM_LIBS)

BUILT_SOURCES = nm-fortisslvpn-pppd-service-glue.h

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = nm-fortisslvpn-pppd-service.xml
