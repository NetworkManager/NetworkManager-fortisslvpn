libexec_PROGRAMS = nm-fortisslvpn-auth-dialog

nm_fortisslvpn_auth_dialog_CPPFLAGS =		\
	$(NM_CFLAGS)				\
	$(GLIB_CFLAGS)				\
	$(GTK_CFLAGS)				\
	$(NMGTK_CFLAGS)				\
	$(LIBSECRET_CFLAGS)			\
	-I$(top_srcdir)				\
	-DUIDIR=\""$(uidir)"\"			\
	-DVERSION=\"$(VERSION)\"

nm_fortisslvpn_auth_dialog_SOURCES =		\
	main.c

nm_fortisslvpn_auth_dialog_LDADD =		\
	$(NM_LIBS)				\
	$(GTK_LIBS)				\
	$(NMGTK_LIBS)				\
	$(LIBSECRET_LIBS)

CLEANFILES = *~
