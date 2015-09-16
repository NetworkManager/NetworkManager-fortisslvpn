/* nm-fortisslvpn-service - SSLVPN integration with NetworkManager
 *
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
 * (C) Copyright 2008 Red Hat, Inc.
 * (C) Copyright 2015 Lubomir Rintel
 */

#ifndef NM_FORTISSLVPN_PLUGIN_H
#define NM_FORTISSLVPN_PLUGIN_H

#include <glib.h>
#include <glib-object.h>
#include <nm-vpn-plugin.h>

#define NM_TYPE_FORTISSLVPN_PLUGIN            (nm_fortisslvpn_plugin_get_type ())
#define NM_FORTISSLVPN_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_FORTISSLVPN_PLUGIN, NMFortisslvpnPlugin))
#define NM_FORTISSLVPN_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_FORTISSLVPN_PLUGIN, NMFortisslvpnPluginClass))
#define NM_IS_FORTISSLVPN_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_FORTISSLVPN_PLUGIN))
#define NM_IS_FORTISSLVPN_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_FORTISSLVPN_PLUGIN))
#define NM_FORTISSLVPN_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_FORTISSLVPN_PLUGIN, NMFortisslvpnPluginClass))

/* For the pppd plugin <-> VPN plugin service */
#define DBUS_TYPE_G_MAP_OF_VARIANT (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))

#define NM_DBUS_SERVICE_FORTISSLVPN_PPP    "org.freedesktop.NetworkManager.fortisslvpn-ppp"
#define NM_DBUS_PATH_FORTISSLVPN_PPP       "/org/freedesktop/NetworkManager/fortisslvpn/ppp"
#define NM_DBUS_INTERFACE_FORTISSLVPN_PPP  "org.freedesktop.NetworkManager.fortisslvpn.ppp"


/* For the NM <-> VPN plugin service */
#define NM_DBUS_SERVICE_FORTISSLVPN    "org.freedesktop.NetworkManager.fortisslvpn"
#define NM_DBUS_INTERFACE_FORTISSLVPN  "org.freedesktop.NetworkManager.fortisslvpn"
#define NM_DBUS_PATH_FORTISSLVPN       "/org/freedesktop/NetworkManager/fortisslvpn"

#define NM_FORTISSLVPN_KEY_GATEWAY           "gateway"
#define NM_FORTISSLVPN_KEY_USER              "user"
#define NM_FORTISSLVPN_KEY_PASSWORD          "password"
#define NM_FORTISSLVPN_KEY_TRUSTED_CERT      "trusted-cert"

typedef struct {
	NMVPNPlugin parent;
} NMFortisslvpnPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NMFortisslvpnPluginClass;

GType nm_fortisslvpn_plugin_get_type (void);

NMFortisslvpnPlugin *nm_fortisslvpn_plugin_new (void);

#endif /* NM_FORTISSLVPN_PLUGIN_H */
