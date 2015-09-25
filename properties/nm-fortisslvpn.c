/***************************************************************************
 * nm-fortisslvpn.c : GNOME UI dialogs for configuring SSLVPN connections
 *
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
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>

#ifdef NM_OPENVPN_OLD

#define NM_VPN_LIBNM_COMPAT
#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-ui-utils.h>

#define nm_simple_connection_new nm_connection_new

#else /* !NM_OPENVPN_OLD */

#include <NetworkManager.h>
#include <nma-ui-utils.h>

#endif

#include "src/nm-fortisslvpn-service-defines.h"
#include "nm-fortisslvpn.h"

#define FORTISSLVPN_PLUGIN_NAME    _("Fortinet SSLVPN")
#define FORTISSLVPN_PLUGIN_DESC    _("Compatible with Fortinet SSLVPN servers.")
#define FORTISSLVPN_PLUGIN_SERVICE NM_DBUS_SERVICE_FORTISSLVPN

typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

/************** plugin class **************/

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void fortisslvpn_plugin_ui_interface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (FortisslvpnPluginUi, fortisslvpn_plugin_ui, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
                                               fortisslvpn_plugin_ui_interface_init))

/************** UI widget class **************/

static void fortisslvpn_plugin_ui_widget_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (FortisslvpnPluginUiWidget, fortisslvpn_plugin_ui_widget, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               fortisslvpn_plugin_ui_widget_interface_init))

#define FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), FORTISSLVPN_TYPE_PLUGIN_UI_WIDGET, FortisslvpnPluginUiWidgetPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
	gboolean new_connection;
	gchar *trusted_cert;
} FortisslvpnPluginUiWidgetPrivate;


GQuark
fortisslvpn_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("fortisslvpn-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
fortisslvpn_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (FORTISSLVPN_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (FORTISSLVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("FortisslvpnPluginUiError", values);
	}
	return etype;
}

static gboolean
check_validity (FortisslvpnPluginUiWidget *self, GError **error)
{
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             FORTISSLVPN_PLUGIN_UI_ERROR,
		             FORTISSLVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_FORTISSLVPN_KEY_GATEWAY);
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (FORTISSLVPN_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
setup_password_widget (FortisslvpnPluginUiWidget *self,
                       const char *entry_name,
                       NMSettingVpn *s_vpn,
                       const char *secret_name,
                       gboolean new_connection)
{
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *value;

	widget = (GtkWidget *) gtk_builder_get_object (priv->builder, entry_name);
	g_assert (widget);
	gtk_size_group_add_widget (priv->group, widget);

	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, secret_name);
		gtk_entry_set_text (GTK_ENTRY (widget), value ? value : "");
	}

	g_signal_connect (widget, "changed", G_CALLBACK (stuff_changed_cb), self);
}

static void
show_toggled_cb (GtkCheckButton *button, FortisslvpnPluginUiWidget *self)
{
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
password_storage_changed_cb (GObject *entry,
                             GParamSpec *pspec,
                             gpointer user_data)
{
	FortisslvpnPluginUiWidget *self = FORTISSLVPN_PLUGIN_UI_WIDGET (user_data);

	stuff_changed_cb (NULL, self);
}

static void
init_password_icon (FortisslvpnPluginUiWidget *self,
                    NMSettingVpn *s_vpn,
                    const char *secret_key,
                    const char *entry_name)
{
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *entry;
	const char *value = NULL;
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;

	/* If there's already a password and the password type can't be found in
	 * the VPN settings, default to saving it.  Otherwise, always ask for it.
	 */
	entry = GTK_WIDGET (gtk_builder_get_object (priv->builder, entry_name));
	g_assert (entry);

	nma_utils_setup_password_storage (entry, 0, (NMSetting *) s_vpn, secret_key,
	                                  TRUE, FALSE);

	/* If there's no password and no flags in the setting,
	 * initialize flags as "always-ask".
	 */
	if (s_vpn)
		nm_setting_get_secret_flags (NM_SETTING (s_vpn), secret_key, &pw_flags, NULL);
	value = gtk_entry_get_text (GTK_ENTRY (entry));
	if ((!value || !*value) && (pw_flags == NM_SETTING_SECRET_FLAG_NONE))
		nma_utils_update_password_storage (entry, NM_SETTING_SECRET_FLAG_NOT_SAVED,
		                                   (NMSetting *) s_vpn, secret_key);

	g_signal_connect (entry, "notify::secondary-icon-name",
	                  G_CALLBACK (password_storage_changed_cb), self);
}

static gboolean
advanced_dialog_delete_cb (GtkWidget *dialog, gpointer user_data)
{
	/* Don't destroy it. */
	return TRUE;
}

static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	FortisslvpnPluginUiWidget *self = FORTISSLVPN_PLUGIN_UI_WIDGET (user_data);
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkEntry *entry = GTK_ENTRY (gtk_builder_get_object (priv->builder, "trusted_cert_entry"));

	g_assert (entry);
	if (response == GTK_RESPONSE_OK) {
		g_free (priv->trusted_cert);
		priv->trusted_cert = g_strdup (gtk_entry_get_text (entry));
		stuff_changed_cb (NULL, self);
	} else {
		gtk_entry_set_text (entry, priv->trusted_cert);
	}

	gtk_widget_hide (dialog);
}

static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	FortisslvpnPluginUiWidget *self = FORTISSLVPN_PLUGIN_UI_WIDGET (user_data);
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *dialog = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_dialog"));
	g_assert (dialog);

	if (!priv->window_added) {
		GtkWidget *toplevel = gtk_widget_get_toplevel (priv->widget);

		g_assert (gtk_widget_is_toplevel (toplevel));
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (toplevel));
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
		gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (toplevel));
		priv->window_added = TRUE;
	}

	gtk_widget_grab_focus (GTK_WIDGET (gtk_builder_get_object (priv->builder, "ok_button")));
	gtk_widget_show_all (dialog);
}

static gboolean
init_plugin_ui (FortisslvpnPluginUiWidget *self, NMConnection *connection, GError **error)
{
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	const char *value;

	s_vpn = (NMSettingVpn *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_FORTISSLVPN_KEY_GATEWAY);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_FORTISSLVPN_KEY_USER);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "trusted_cert_entry"));
	if (!widget)
		return FALSE;
	if (s_vpn) {
		priv->trusted_cert = g_strdup (nm_setting_vpn_get_data_item (s_vpn,
		                                                             NM_FORTISSLVPN_KEY_TRUSTED_CERT));
		if (!priv->trusted_cert)
			priv->trusted_cert = g_strdup ("");
		gtk_entry_set_text (GTK_ENTRY (widget), priv->trusted_cert);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "show_passwords_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  self);

	/* Fill the VPN passwords *before* initializing the PW type combo, since
	 * knowing if there is a password when initializing the type combo is helpful.
	 */
	setup_password_widget (self,
	                       "user_password_entry",
	                       s_vpn,
	                       NM_FORTISSLVPN_KEY_PASSWORD,
	                       priv->new_connection);

	init_password_icon (self,
	                    s_vpn,
	                    NM_FORTISSLVPN_KEY_PASSWORD,
	                    "user_password_entry");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ca_chooser"));
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_FORTISSLVPN_KEY_CA);
		if (value && strlen (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "update-preview", G_CALLBACK (stuff_changed_cb), self);


	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_dialog"));
	if (!widget)
		return FALSE;
	g_signal_connect (G_OBJECT (widget), "response", G_CALLBACK (advanced_dialog_response_cb), self);
	g_signal_connect (G_OBJECT (widget), "delete-event", G_CALLBACK (advanced_dialog_delete_cb), NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
	if (!widget)
		return FALSE;
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	FortisslvpnPluginUiWidget *self = FORTISSLVPN_PLUGIN_UI_WIDGET (iface);
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
save_password_and_flags (NMSettingVpn *s_vpn,
                         GtkBuilder *builder,
                         const char *entry_name,
                         const char *secret_key)
{
	NMSettingSecretFlags flags;
	const char *password;
	GtkWidget *entry;

	/* Get secret flags */
	entry = GTK_WIDGET (gtk_builder_get_object (builder, entry_name));
	flags = nma_utils_menu_to_secret_flags (entry);

	/* Save password and convert flags to legacy data items */
	switch (flags) {
	case NM_SETTING_SECRET_FLAG_NONE:
	case NM_SETTING_SECRET_FLAG_AGENT_OWNED:
		password = gtk_entry_get_text (GTK_ENTRY (entry));
		if (password && strlen (password))
			nm_setting_vpn_add_secret (s_vpn, secret_key, password);
		break;
	default:
		break;
	}

	/* Set new secret flags */
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), secret_key, flags, NULL);
}

static gboolean
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
	FortisslvpnPluginUiWidget *self = FORTISSLVPN_PLUGIN_UI_WIDGET (iface);
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	const char *str;
	gboolean valid = FALSE;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_FORTISSLVPN, NULL);

	/* Gateway */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_GATEWAY, str);

	/* Username */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_USER, str);

	/* User password and flags */
	save_password_and_flags (s_vpn,
	                         priv->builder,
	                         "user_password_entry",
	                         NM_FORTISSLVPN_KEY_PASSWORD);

	/* CA file */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ca_chooser"));
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_FORTISSLVPN_KEY_CA, str);

	/* Trusted certificate */
	if (priv->trusted_cert && strlen (priv->trusted_cert))
		nm_setting_vpn_add_data_item (s_vpn,
		                              NM_FORTISSLVPN_KEY_TRUSTED_CERT,
		                              priv->trusted_cert);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

static void
is_new_func (const char *key, const char *value, gpointer user_data)
{
	gboolean *is_new = user_data;

	/* If there are any VPN data items the connection isn't new */
	*is_new = FALSE;
}

static NMVpnEditor *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	FortisslvpnPluginUiWidgetPrivate *priv;
	char *ui_file;
	gboolean new = TRUE;
	NMSettingVpn *s_vpn;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = g_object_new (FORTISSLVPN_TYPE_PLUGIN_UI_WIDGET, NULL);
	if (!object) {
		g_set_error (error, FORTISSLVPN_PLUGIN_UI_ERROR, 0, "could not create fortisslvpn object");
		return NULL;
	}

	priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-fortisslvpn-dialog.ui");
	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_file (priv->builder, ui_file, error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
		g_clear_error (error);
		g_set_error (error, FORTISSLVPN_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (ui_file);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "fortisslvpn-vbox"));
	if (!priv->widget) {
		g_set_error (error, FORTISSLVPN_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);
	priv->new_connection = new;

	if (!init_plugin_ui (FORTISSLVPN_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	FortisslvpnPluginUiWidget *plugin = FORTISSLVPN_PLUGIN_UI_WIDGET (object);
	FortisslvpnPluginUiWidgetPrivate *priv = FORTISSLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
	g_signal_handlers_disconnect_by_func (G_OBJECT (widget),
	                                      (GCallback) password_storage_changed_cb,
	                                      plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->builder)
		g_object_unref (priv->builder);

	G_OBJECT_CLASS (fortisslvpn_plugin_ui_widget_parent_class)->dispose (object);
}

static void
fortisslvpn_plugin_ui_widget_class_init (FortisslvpnPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (FortisslvpnPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
fortisslvpn_plugin_ui_widget_init (FortisslvpnPluginUiWidget *plugin)
{
}

static void
fortisslvpn_plugin_ui_widget_interface_init (NMVpnEditorInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
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
fortisslvpn_plugin_ui_class_init (FortisslvpnPluginUiClass *req_class)
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

static void
fortisslvpn_plugin_ui_init (FortisslvpnPluginUi *plugin)
{
}

static void
fortisslvpn_plugin_ui_interface_init (NMVpnEditorPluginInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = NULL;
	iface_class->export_to_file = NULL;
	iface_class->get_suggested_filename = NULL;
}


G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	return g_object_new (FORTISSLVPN_TYPE_PLUGIN_UI, NULL);
}

