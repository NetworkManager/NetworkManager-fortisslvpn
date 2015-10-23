libexec_PROGRAMS = nm-fortisslvpn-auth-dialog

nm_fortisslvpn_auth_dialog_CPPFLAGS =		\
	$(LIBNM_CFLAGS)				\
	$(GLIB_CFLAGS)				\
	$(GTK_CFLAGS)				\
	$(LIBNMA_CFLAGS)			\
	$(LIBSECRET_CFLAGS)			\
	-I$(top_srcdir)				\
	-DUIDIR=\""$(uidir)"\"

nm_fortisslvpn_auth_dialog_SOURCES =		\
	main.c

nm_fortisslvpn_auth_dialog_LDADD =		\
	$(LIBNM_LIBS)				\
	$(GTK_LIBS)				\
	$(LIBNMA_LIBS)				\
	$(LIBSECRET_LIBS)

CLEANFILES = *~
