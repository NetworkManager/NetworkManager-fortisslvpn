/***************************************************************************
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
 **************************************************************************/

#ifndef __NM_FORTISSLVPN_EDITOR_PLUGIN_H__
#define __NM_FORTISSLVPN_EDITOR_PLUGIN_H__

#define FORTISSLVPN_TYPE_EDITOR_PLUGIN            (fortisslvpn_editor_plugin_get_type ())
#define FORTISSLVPN_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), FORTISSLVPN_TYPE_EDITOR_PLUGIN, FortisslvpnEditorPlugin))
#define FORTISSLVPN_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), FORTISSLVPN_TYPE_EDITOR_PLUGIN, FortisslvpnEditorPluginClass))
#define FORTISSLVPN_IS_EDITOR_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FORTISSLVPN_TYPE_EDITOR_PLUGIN))
#define FORTISSLVPN_IS_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), FORTISSLVPN_TYPE_EDITOR_PLUGIN))
#define FORTISSLVPN_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), FORTISSLVPN_TYPE_EDITOR_PLUGIN, FortisslvpnEditorPluginClass))

typedef struct _FortisslvpnEditorPlugin FortisslvpnEditorPlugin;
typedef struct _FortisslvpnEditorPluginClass FortisslvpnEditorPluginClass;

struct _FortisslvpnEditorPlugin {
	GObject parent;
};

struct _FortisslvpnEditorPluginClass {
	GObjectClass parent;
};

GType fortisslvpn_editor_plugin_get_type (void);

typedef NMVpnEditor *(*NMVpnEditorFactory) (NMVpnEditorPlugin *editor_plugin,
                                            NMConnection *connection,
                                            GError **error);

NMVpnEditor *
nm_vpn_editor_factory_fortisslvpn (NMVpnEditorPlugin *editor_plugin,
                                   NMConnection *connection,
                                   GError **error);

#endif /* __NM_FORTISSLVPN_EDITOR_PLUGIN_H__ */
