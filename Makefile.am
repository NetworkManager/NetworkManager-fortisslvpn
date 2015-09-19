AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

if WITH_GNOME
SUBDIRS += auth-dialog properties po
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-fortisslvpn-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-fortisslvpn-service.name

nm-fortisslvpn-service.name: $(srcdir)/nm-fortisslvpn-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|$(libdir)/NetworkManager|g' \
	    $< >$@

DISTCHECK_CONFIGURE_FLAGS = --enable-more-warnings=yes

EXTRA_DIST = nm-fortisslvpn-service.name.in		\
	$(dbusservice_DATA)				\
	$(desktopfile)					\
	$(iconfile)					\
	intltool-extract.in				\
	intltool-merge.in				\
	intltool-update.in				\
	contrib/README					\
	contrib/fortiserve.pl				\
	contrib/sslproxy.pl

CLEANFILES = $(nmvpnservice_DATA) $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
