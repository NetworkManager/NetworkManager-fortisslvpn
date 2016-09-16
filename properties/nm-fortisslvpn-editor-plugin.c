/***************************************************************************
 * Copyright (C) 2015 Lubomir Rintel <lkundrak@v3.sk>
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 * Based on work by David Zeuthen, <davidz@redhat.com>
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

#include "nm-default.h"

#include "nm-fortisslvpn-editor-plugin.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "nm-fortisslvpn-editor.h"

#define FORTISSLVPN_PLUGIN_NAME    _("Fortinet SSLVPN")
#define FORTISSLVPN_PLUGIN_DESC    _("Compatible with Fortinet SSLVPN servers.")
#define FORTISSLVPN_PLUGIN_SERVICE NM_DBUS_SERVICE_FORTISSLVPN

/*****************************************************************************/

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void fortisslvpn_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (FortisslvpnEditorPlugin, fortisslvpn_editor_plugin, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
                                               fortisslvpn_editor_plugin_interface_init))

/*****************************************************************************/

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	return nm_fortisslvpn_editor_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, FORTISSLVPN_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, FORTISSLVPN_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, FORTISSLVPN_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
fortisslvpn_editor_plugin_init (FortisslvpnEditorPlugin *plugin)
{
}

static void
fortisslvpn_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = NULL;
	iface_class->export_to_file = NULL;
	iface_class->get_suggested_filename = NULL;
}

static void
fortisslvpn_editor_plugin_class_init (FortisslvpnEditorPluginClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
	                                  PROP_NAME,
	                                  NM_VPN_EDITOR_PLUGIN_NAME);

	g_object_class_override_property (object_class,
	                                  PROP_DESC,
	                                  NM_VPN_EDITOR_PLUGIN_DESCRIPTION);

	g_object_class_override_property (object_class,
	                                  PROP_SERVICE,
	                                  NM_VPN_EDITOR_PLUGIN_SERVICE);
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	return g_object_new (FORTISSLVPN_TYPE_EDITOR_PLUGIN, NULL);
}

