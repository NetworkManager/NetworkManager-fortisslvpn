AUTOMAKE_OPTIONS = foreign subdir-objects

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=yes

libexec_PROGRAMS =

noinst_LTLIBRARIES =

EXTRA_DIST =

CLEANFILES =

noinst_PROGRAMS =

SUBDIRS = \
	. \
	po

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES =

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-fortisslvpn-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-fortisslvpn-service.name

BUILT_SOURCES =

###############################################################################

src_cppflags = \
        $(GLIB_CFLAGS) \
        $(LIBNM_CFLAGS) \
	-I$(srcdir)/shared \
	-I$(builddir)/src \
        -DNM_FORTISSLVPN_LOCALEDIR=\"$(datadir)/locale\" \
        -DNM_FORTISSLVPN_STATEDIR=\"$(fortisslvpn_statedir)\" \
        -DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\"

###############################################################################

noinst_LTLIBRARIES += src/libnm-fortisslvpn-pppd-service-dbus.la

nodist_src_libnm_fortisslvpn_pppd_service_dbus_la_SOURCES = \
	src/nm-fortisslvpn-pppd-service-dbus.c \
	src/nm-fortisslvpn-pppd-service-dbus.h

src_libnm_fortisslvpn_pppd_service_dbus_la_CPPFLAGS = \
	$(src_cppflags) \
	$(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

src/nm-fortisslvpn-pppd-service-dbus.h: $(top_srcdir)/src/nm-fortisslvpn-pppd-service.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

src/nm-fortisslvpn-pppd-service-dbus.c: src/nm-fortisslvpn-pppd-service-dbus.h
	@true

BUILT_SOURCES += \
	src/nm-fortisslvpn-pppd-service-dbus.h \
	src/nm-fortisslvpn-pppd-service-dbus.c

CLEANFILES += \
	src/nm-fortisslvpn-pppd-service-dbus.h \
	src/nm-fortisslvpn-pppd-service-dbus.c

EXTRA_DIST += \
	src/nm-fortisslvpn-pppd-service.xml

###############################################################################

libexec_PROGRAMS += src/nm-fortisslvpn-service

src_nm_fortisslvpn_service_SOURCES = \
	shared/nm-utils/nm-shared-utils.c \
	src/nm-ppp-status.h \
	src/nm-fortisslvpn-service.h \
	src/nm-fortisslvpn-service.c
src_nm_fortisslvpn_service_CPPFLAGS = $(src_cppflags)
src_nm_fortisslvpn_service_LDADD = \
	src/libnm-fortisslvpn-pppd-service-dbus.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

###############################################################################

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = src/nm-fortisslvpn-pppd-plugin.la

src_nm_fortisslvpn_pppd_plugin_la_SOURCES = \
	src/nm-fortisslvpn-pppd-plugin.c \
	src/nm-ppp-status.h
src_nm_fortisslvpn_pppd_plugin_la_CPPFLAGS = $(src_cppflags)
src_nm_fortisslvpn_pppd_plugin_la_LDFLAGS = \
	-module -avoid-version
src_nm_fortisslvpn_pppd_plugin_la_LIBADD = \
	src/libnm-fortisslvpn-pppd-service-dbus.la \
	$(GLIB_LIBS)
	$(LIBNM_LIBS)

###############################################################################

properties/resources.h: properties/gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-header --internal

properties/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir)/properties --generate-dependencies $(srcdir)/properties/gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-source --internal

plugin_sources = \
	properties/nm-fortisslvpn-editor-plugin.c \
	properties/nm-fortisslvpn-editor-plugin.h

editor_sources = \
	properties/resources.c \
	properties/resources.h \
	properties/nm-fortisslvpn-editor.c \
	properties/nm-fortisslvpn-editor.h

properties_cppflags = \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS)

CLEANFILES += \
	properties/resources.c \
	properties/resources.h

EXTRA_DIST += \
	properties/gresource.xml

###############################################################################

noinst_LTLIBRARIES += properties/libnm-vpn-plugin-fortisslvpn-utils.la

properties_libnm_vpn_plugin_fortisslvpn_utils_la_SOURCES = \
	$(shared_sources)

properties_libnm_vpn_plugin_fortisslvpn_utils_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(properties_cppflags) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_fortisslvpn_utils_la_LIBADD = \
	$(LIBNM_LIBS) \
	$(DL_LIBS)

noinst_LTLIBRARIES += properties/libnm-vpn-plugin-fortisslvpn-core.la

properties_libnm_vpn_plugin_fortisslvpn_core_la_SOURCES = \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	$(plugin_sources)

properties_libnm_vpn_plugin_fortisslvpn_core_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(properties_cppflags) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_fortisslvpn_core_la_LIBADD = \
	properties/libnm-vpn-plugin-fortisslvpn-utils.la \
	$(LIBNM_LIBS) \
	$(DL_LIBS)

plugin_LTLIBRARIES += properties/libnm-vpn-plugin-fortisslvpn.la

properties_libnm_vpn_plugin_fortisslvpn_la_SOURCES =
properties_libnm_vpn_plugin_fortisslvpn_la_LIBADD = \
	properties/libnm-vpn-plugin-fortisslvpn-core.la
properties_libnm_vpn_plugin_fortisslvpn_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-fortisslvpn.ver

###############################################################################

if WITH_GNOME
plugin_LTLIBRARIES += properties/libnm-vpn-plugin-fortisslvpn-editor.la
endif

properties_libnm_vpn_plugin_fortisslvpn_editor_la_SOURCES = \
	$(editor_sources)

properties_libnm_vpn_plugin_fortisslvpn_editor_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(properties_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

properties_libnm_vpn_plugin_fortisslvpn_editor_la_LIBADD = \
	properties/libnm-vpn-plugin-fortisslvpn-utils.la \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

properties_libnm_vpn_plugin_fortisslvpn_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-vpn-plugin-fortisslvpn-editor.ver

###############################################################################

if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += properties/libnm-fortisslvpn-properties-core.la
endif

properties_libnm_fortisslvpn_properties_core_la_SOURCES = \
	$(shared_sources) \
	$(plugin_sources) \
	$(editor_sources)

properties_libnm_fortisslvpn_properties_core_la_CPPFLAGS = \
	-DNM_VPN_OLD \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(properties_cppflags) \
	$(GTK_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS)

properties_libnm_fortisslvpn_properties_core_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS)


if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += properties/libnm-fortisslvpn-properties.la
endif

properties_libnm_fortisslvpn_properties_la_SOURCES =
properties_libnm_fortisslvpn_properties_la_LIBADD = \
	properties/libnm-fortisslvpn-properties-core.la
properties_libnm_fortisslvpn_properties_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script=$(srcdir)/properties/libnm-fortisslvpn-properties.ver

EXTRA_DIST += \
	properties/libnm-vpn-plugin-fortisslvpn.ver \
	properties/libnm-vpn-plugin-fortisslvpn-editor.ver \
	properties/libnm-fortisslvpn-properties.ver \
	properties/nm-fortisslvpn-dialog.ui

###############################################################################

if WITH_GNOME
libexec_PROGRAMS += auth-dialog/nm-fortisslvpn-auth-dialog
endif

auth_dialog_nm_fortisslvpn_auth_dialog_SOURCES = \
	$(shared_sources) \
	auth-dialog/main.c
auth_dialog_nm_fortisslvpn_auth_dialog_CPPFLAGS = \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(LIBSECRET_CFLAGS)
auth_dialog_nm_fortisslvpn_auth_dialog_LDADD = \
	$(GLIB_LIBS) \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)

###############################################################################

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
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_files)
endif
appdata_in_files = appdata/network-manager-fortisslvpn.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-fortisslvpn-service.name: $(srcdir)/nm-fortisslvpn-service.name.in
	$(AM_V_GEN) sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $^ >$@

EXTRA_DIST += \
	nm-fortisslvpn-service.name.in \
	$(dbusservice_DATA) \
	$(appdata_in_files) \
	$(appdata_files) \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	\
	shared/README \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-default.h \
	shared/nm-service-defines.h \
	$(NULL)

CLEANFILES += \
	$(nmvpnservice_DATA) \
	$(appdata_files)

DISTCLEANFILES = \
	intltool-extract \
	intltool-merge \
	intltool-update

ACLOCAL_AMFLAGS = -I m4
