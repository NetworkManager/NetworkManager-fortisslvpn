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
#include "nm-fortissl-properties.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef NM_VPN_OLD
#include "nm-fortisslvpn-editor.h"
#else
#include "nm-utils/nm-vpn-plugin-utils.h"
#endif

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
	return   NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT
	       | NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT;
}

#ifndef NM_VPN_OLD
static NMVpnEditor *
_call_editor_factory (gpointer factory,
                      NMVpnEditorPlugin *editor_plugin,
                      NMConnection *connection,
                      gpointer user_data,
                      GError **error)
{
	return ((NMVpnEditorFactory) factory) (editor_plugin,
	                                       connection,
	                                       error);
}
#endif

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	g_return_val_if_fail (FORTISSLVPN_IS_EDITOR_PLUGIN (iface), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	{
#ifdef NM_VPN_OLD
		return nm_fortisslvpn_editor_new (connection, error);
#else
		return nm_vpn_plugin_utils_load_editor ("libnm-vpn-plugin-fortisslvpn-editor.so",
		                                        "nm_vpn_editor_factory_fortisslvpn",
		                                        _call_editor_factory,
		                                        iface,
		                                        connection,
		                                        NULL,
		                                        error);
#endif
	}
}

static NMConnection *
import_from_file (NMVpnEditorPlugin *iface, const char *filename,
                  GError **error)
{
	gs_unref_object GFile *file = NULL;
	gs_unref_object GFileInputStream *stream = NULL;
	gs_unref_object GDataInputStream *data = NULL;
	gs_unref_object NMSettingVpn *s_vpn = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_free char *basename = NULL;
	gs_free char *host = NULL;
	gs_free char *port = NULL;
	GError *local = NULL;
	char *line;
	gchar **words;

	file = g_file_new_for_path (filename);
	basename = g_file_get_basename (file);
	stream = g_file_read (file, NULL, error);
	if (!stream) {
		g_prefix_error (error, _("Can not open input file: "));
		return FALSE;
	}

	s_vpn = g_object_new (NM_TYPE_SETTING_VPN,
	                      NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_FORTISSLVPN,
	                      NULL);

	data = g_data_input_stream_new (G_INPUT_STREAM (stream));
	while ((line = g_data_input_stream_read_line (data, NULL, NULL, &local))) {
		if (local) {
			g_propagate_prefixed_error (error, local,
			                            _("Error reading input file: "));
			return FALSE;
		}
		words = g_strsplit (line, "=", 2);
		g_free (line);
		if (words[0] && words[1]) {
			g_strchomp (words[0]);
			g_strchug (words[1]);
			if (strcmp (words[0], "host") == 0) {
				g_clear_pointer (&host, g_free);
				host = g_steal_pointer (&words[1]);
			} else if (strcmp (words[0], "port") == 0) {
				g_clear_pointer (&port, g_free);
				port = g_steal_pointer (&words[1]);
			} else if (strcmp (words[0], "username") == 0) {
				nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_USER, words[1]);
			} else if (strcmp (words[0], "password") == 0) {
				nm_setting_vpn_add_secret (s_vpn, NM_FORTISSLVPN_KEY_PASSWORD, words[1]);
			} else if (strcmp (words[0], "otp") == 0) {
				nm_setting_vpn_add_secret (s_vpn, NM_FORTISSLVPN_KEY_OTP, words[1]);
			} else if (strcmp (words[0], "ca-file") == 0) {
				nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_CA, words[1]);
			} else if (strcmp (words[0], "user-cert") == 0) {
				nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_CERT, words[1]);
			} else if (strcmp (words[0], "user-key") == 0) {
				nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_KEY, words[1]);
			} else if (strcmp (words[0], "trusted-cert") == 0) {
				nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_TRUSTED_CERT, words[1]);
			} else if (strcmp (words[0], "realm") == 0) {
				nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_REALM, words[1]);
			} else if (*words[0] != '#') {
				g_set_error (error, NMV_EDITOR_PLUGIN_ERROR,
				             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
				             _("Unreconigzed token: '%s'"), words[0]);
				g_strfreev (words);
				return FALSE;
			}
		}
		g_strfreev (words);
	}

	if (host) {
		line = g_strdup_printf ("%s%s%s", host, port ? ":" : "", port ?: "");
		nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_GATEWAY, line);
		g_free (line);
	}

	if (!nm_fortisslvpn_properties_validate (s_vpn, error))
		return FALSE;

	connection = nm_simple_connection_new ();

	nm_connection_add_setting (connection,
		g_object_new (NM_TYPE_SETTING_CONNECTION,
		              NM_SETTING_CONNECTION_ID, basename,
		              NULL));

	nm_connection_add_setting (connection, g_steal_pointer (&s_vpn));
	nm_connection_dump (connection);

	if (!nm_connection_normalize (connection, NULL, NULL, error))
		return FALSE;

	return g_steal_pointer (&connection);
}

static gboolean
export_to_file (NMVpnEditorPlugin *iface, const char *filename,
                NMConnection *connection, GError **error)
{
	gs_unref_object GFile *file = NULL;
	gs_unref_object GFileOutputStream *stream = NULL;
	NMSettingVpn *s_vpn;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));

	file = g_file_new_for_path (filename);
	stream = g_file_replace (file, NULL, FALSE, G_FILE_CREATE_REPLACE_DESTINATION, NULL, error);
	if (!stream) {
		g_prefix_error (error, _("Can not open output file: "));
		return FALSE;
	}

	if (!nm_fortisslvpn_write_config (G_OUTPUT_STREAM (stream), s_vpn, error)) {
		g_prefix_error (error, _("Can not write output file: "));
		return FALSE;
	}

	return TRUE;
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
	iface_class->import_from_file = import_from_file;
	iface_class->export_to_file = export_to_file;
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

