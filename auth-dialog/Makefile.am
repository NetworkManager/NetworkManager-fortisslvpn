libexec_PROGRAMS = nm-fortisslvpn-auth-dialog

nm_fortisslvpn_auth_dialog_CPPFLAGS =		\
	$(LIBNM_GLIB_CFLAGS)			\
	$(GLIB_CFLAGS)				\
	$(GTK_CFLAGS)				\
	$(LIBNM_GTK_CFLAGS)			\
	$(LIBSECRET_CFLAGS)			\
	-I$(top_srcdir)				\
	-DUIDIR=\""$(uidir)"\"			\
	-DVERSION=\"$(VERSION)\"

nm_fortisslvpn_auth_dialog_SOURCES =		\
	main.c

nm_fortisslvpn_auth_dialog_LDADD =		\
	$(LIBNM_GLIB_LIBS)			\
	$(GTK_LIBS)				\
	$(LIBNM_GTK_LIBS)			\
	$(LIBSECRET_LIBS)

CLEANFILES = *~
