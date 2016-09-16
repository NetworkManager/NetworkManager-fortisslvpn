/***************************************************************************
 * nm-fortisslvpn.h : GNOME UI dialogs for configuring fortisslvpn VPN connections
 *
 * Copyright (C) 2015 Lubomir Rintel <lkundrak@v3.sk>
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#ifndef _NM_FORTISSLVPN_H_
#define _NM_FORTISSLVPN_H_

#define FORTISSLVPN_TYPE_EDITOR            (fortisslvpn_editor_get_type ())
#define FORTISSLVPN_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), FORTISSLVPN_TYPE_EDITOR, FortisslvpnEditor))
#define FORTISSLVPN_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), FORTISSLVPN_TYPE_EDITOR, FortisslvpnEditorClass))
#define FORTISSLVPN_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FORTISSLVPN_TYPE_EDITOR))
#define FORTISSLVPN_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), FORTISSLVPN_TYPE_EDITOR))
#define FORTISSLVPN_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), FORTISSLVPN_TYPE_EDITOR, FortisslvpnEditorClass))

typedef struct _FortisslvpnEditor FortisslvpnEditor;
typedef struct _FortisslvpnEditorClass FortisslvpnEditorClass;

struct _FortisslvpnEditor {
	GObject parent;
};

struct _FortisslvpnEditorClass {
	GObjectClass parent;
};

GType fortisslvpn_editor_get_type (void);

NMVpnEditor *nm_fortisslvpn_editor_new (NMConnection *connection, GError **error);

#endif /* _NM_FORTISSLVPN_H_ */
