/*
 * Lubomir Rintel <lkundrak@v3.sk>
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2008 - 2014 Red Hat, Inc.
 * (C) Copyright 2015,2017,2019 Lubomir Rintel
 */

#include "nm-default.h"
#include "nm-fortissl-properties.h"

#include <sys/stat.h>
#include <ctype.h>

typedef struct {
	const char *name;
	GType type;
	bool required:1;
} ValidProperty;

static const ValidProperty valid_properties[] = {
	{ NM_FORTISSLVPN_KEY_GATEWAY,           G_TYPE_STRING, TRUE },
	{ NM_FORTISSLVPN_KEY_USER,              G_TYPE_STRING, FALSE },
	{ NM_FORTISSLVPN_KEY_CA,                G_TYPE_STRING, FALSE },
	{ NM_FORTISSLVPN_KEY_TRUSTED_CERT,      G_TYPE_STRING, FALSE },
	{ NM_FORTISSLVPN_KEY_CERT,              G_TYPE_STRING, FALSE },
	{ NM_FORTISSLVPN_KEY_KEY,               G_TYPE_STRING, FALSE },
	{ NM_FORTISSLVPN_KEY_REALM,             G_TYPE_STRING, FALSE },
	{ NM_FORTISSLVPN_KEY_PASSWORD"-flags",  G_TYPE_UINT,   FALSE },
	{ NM_FORTISSLVPN_KEY_OTP"-flags",       G_TYPE_UINT,   FALSE },
	{ NULL }
};

static const ValidProperty valid_secrets[] = {
	{ NM_FORTISSLVPN_KEY_PASSWORD,          G_TYPE_STRING, TRUE },
	{ NM_FORTISSLVPN_KEY_OTP,               G_TYPE_STRING, TRUE },
	{ NULL }
};

static gboolean
validate_gateway (const char *gateway)
{
	if (!gateway || !strlen (gateway) || !isalnum (*gateway))
		return FALSE;

	return TRUE;
}

/* This is a bit half-assed. We should check that the user doesn't
 * abuse this to access files he ordinarily shouldn't, but we can't do
 * any better than this for we don't have any information about the
 * identity of the user that activates the connection.
 * We should probably get the certificate inline or something. */
static gboolean
validate_ca (const char *ca)
{
	struct stat ca_stat;

	/* Tolerate only absolute paths */
	if (!ca || !strlen (ca) || *ca != '/')
		return FALSE;

	if (stat (ca, &ca_stat) == -1)
		return FALSE;

	/* Allow only ordinary files */
	if (!(ca_stat.st_mode & S_IFREG))
		return FALSE;

	/* Allow only world-readable files */
	if ((ca_stat.st_mode & 0444) != 0444)
		return FALSE;

	return TRUE;
}

typedef struct ValidateInfo {
	const ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			if (   !strcmp (prop.name, NM_FORTISSLVPN_KEY_GATEWAY)
			    && !validate_gateway (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid gateway “%s”"),
				             value);
				return;
			} else if (   !strcmp (prop.name, NM_FORTISSLVPN_KEY_CA)
			           && !validate_ca (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid certificate authority “%s”"),
				             value);
				return;
			}
			return; /* valid */
		case G_TYPE_UINT:
			errno = 0;
			(void) strtol (value, NULL, 10);
			if (errno == 0)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid integer property “%s”"),
			             key);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid boolean property “%s” (not yes or no)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property “%s” type %s"),
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property “%s” invalid or not supported"),
		             key);
	}
}

gboolean
nm_fortisslvpn_properties_validate (NMSettingVpn *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };
	int i;

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN configuration options."));
		return FALSE;
	}

	if (*error)
		return FALSE;

	/* Ensure required properties exist */
	for (i = 0; valid_properties[i].name; i++) {
		ValidProperty prop = valid_properties[i];
		const char *value;

		if (!prop.required)
			continue;

		value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
		if (!value || !strlen (value)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Missing required option “%s”."),
			             prop.name);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
nm_fortisslvpn_properties_validate_secrets (NMSettingVpn *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

  const char *cert;
  cert = nm_setting_vpn_get_data_item (s_vpn, NM_FORTISSLVPN_KEY_CERT);

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		if (!cert) {
			g_set_error (error,
				NM_VPN_PLUGIN_ERROR,
				NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				"%s",
				_("No VPN secrets!"));
			return FALSE;
		}
	}

	return *error ? FALSE : TRUE;
}
