fortisslvpn_statedir = $(sharedstatedir)/$(PACKAGE)

install-data-hook:
	$(mkinstalldirs) -m 0700 $(DESTDIR)$(fortisslvpn_statedir)

AM_CPPFLAGS =							\
	$(GLIB_CFLAGS)						\
	$(LIBNM_CFLAGS)						\
	-I$(top_srcdir)						\
	-DNM_FORTISSLVPN_LOCALEDIR=\"$(datadir)/locale\"	\
	-DNM_FORTISSLVPN_STATEDIR=\"$(fortisslvpn_statedir)\"	\
	-DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\" 

libexec_PROGRAMS = nm-fortisslvpn-service

nm_fortisslvpn_service_SOURCES =				\
	nm-fortisslvpn-service.c				\
	nm-fortisslvpn-service-defines.h			\
	nm-fortisslvpn-service.h

# D-Bus stuff
noinst_LTLIBRARIES = libnm-fortisslvpn-pppd-service-dbus.la

nodist_libnm_fortisslvpn_pppd_service_dbus_la_SOURCES =		\
	nm-fortisslvpn-pppd-service-dbus.c			\
	nm-fortisslvpn-pppd-service-dbus.h

libnm_fortisslvpn_pppd_service_dbus_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

nm-fortisslvpn-pppd-service-dbus.h: $(top_srcdir)/src/nm-fortisslvpn-pppd-service.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

nm-fortisslvpn-pppd-service-dbus.c:
	@true

nm_fortisslvpn_service_LDADD =					\
	$(GLIB_LIBS)						\
	$(LIBNM_LIBS)						\
	libnm-fortisslvpn-pppd-service-dbus.la

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-fortisslvpn-pppd-plugin.la

nm_fortisslvpn_pppd_plugin_la_SOURCES =				\
	nm-fortisslvpn-pppd-plugin.c				\
	nm-ppp-status.h

nm_fortisslvpn_pppd_plugin_la_CPPFLAGS =			\
	$(GLIB_CFLAGS)						\
	$(LIBNM_CFLAGS)

nm_fortisslvpn_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_fortisslvpn_pppd_plugin_la_LIBADD =				\
	$(GLIB_LIBS)						\
	$(LIBNM_LIBS)

BUILT_SOURCES = nm-fortisslvpn-pppd-service-dbus.h nm-fortisslvpn-pppd-service-dbus.c

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = nm-fortisslvpn-pppd-service.xml
