/* nm-fortisslvpn-service - SSLVPN integration with NetworkManager
 *
 * (C) 2015 Lubomir Rintel
 * (C) 2007 - 2008 Novell, Inc.
 * (C) 2008 - 2009 Red Hat, Inc.
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
 * 
 */

#include <string.h>
#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <stdlib.h>

#include "nm-fortisslvpn-service.h"
#include "nm-ppp-status.h"

#include <nm-utils.h>

/* These are here because nm-dbus-glib-types.h isn't exported */
#define DBUS_TYPE_G_ARRAY_OF_UINT          (dbus_g_type_get_collection ("GArray", G_TYPE_UINT))
#define DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_ARRAY_OF_UINT))

int plugin_init (void);

char pppd_version[] = VERSION;

static DBusGProxy *proxy = NULL;

static void
nm_phasechange (void *data, int arg)
{
	NMPPPStatus ppp_status = NM_PPP_STATUS_UNKNOWN;
	char *ppp_phase;

	g_return_if_fail (DBUS_IS_G_PROXY (proxy));

	switch (arg) {
	case PHASE_DEAD:
		ppp_status = NM_PPP_STATUS_DEAD;
		ppp_phase = "dead";
		break;
	case PHASE_INITIALIZE:
		ppp_status = NM_PPP_STATUS_INITIALIZE;
		ppp_phase = "initialize";
		break;
	case PHASE_SERIALCONN:
		ppp_status = NM_PPP_STATUS_SERIALCONN;
		ppp_phase = "serial connection";
		break;
	case PHASE_DORMANT:
		ppp_status = NM_PPP_STATUS_DORMANT;
		ppp_phase = "dormant";
		break;
	case PHASE_ESTABLISH:
		ppp_status = NM_PPP_STATUS_ESTABLISH;
		ppp_phase = "establish";
		break;
	case PHASE_AUTHENTICATE:
		ppp_status = NM_PPP_STATUS_AUTHENTICATE;
		ppp_phase = "authenticate";
		break;
	case PHASE_CALLBACK:
		ppp_status = NM_PPP_STATUS_CALLBACK;
		ppp_phase = "callback";
		break;
	case PHASE_NETWORK:
		ppp_status = NM_PPP_STATUS_NETWORK;
		ppp_phase = "network";
		break;
	case PHASE_RUNNING:
		ppp_status = NM_PPP_STATUS_RUNNING;
		ppp_phase = "running";
		break;
	case PHASE_TERMINATE:
		ppp_status = NM_PPP_STATUS_TERMINATE;
		ppp_phase = "terminate";
		break;
	case PHASE_DISCONNECT:
		ppp_status = NM_PPP_STATUS_DISCONNECT;
		ppp_phase = "disconnect";
		break;
	case PHASE_HOLDOFF:
		ppp_status = NM_PPP_STATUS_HOLDOFF;
		ppp_phase = "holdoff";
		break;
	case PHASE_MASTER:
		ppp_status = NM_PPP_STATUS_MASTER;
		ppp_phase = "master";
		break;

	default:
		ppp_phase = "unknown";
		break;
	}

	g_message ("nm-fortisslvpn-ppp-plugin: (%s): status %d / phase '%s'",
	           __func__,
	           ppp_status,
	           ppp_phase);

	if (ppp_status != NM_PPP_STATUS_UNKNOWN) {
		dbus_g_proxy_call_no_reply (proxy, "SetState",
		                            G_TYPE_UINT, ppp_status,
		                            G_TYPE_INVALID,
		                            G_TYPE_INVALID);
	}
}

static GValue *
str_to_gvalue (const char *str)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static GValue *
uint_to_gvalue (guint32 i)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, i);

	return val;
}

static void
value_destroy (gpointer data)
{
	GValue *val = (GValue *) data;

	g_value_unset (val);
	g_slice_free (GValue, val);
}

static GValue *
get_ip4_routes (in_addr_t ouraddr)
{
	GPtrArray *routes;
	GValue *value = NULL;
	int i;

	routes = g_ptr_array_new ();

	for (i = 0; i < 100; i++) {
		GArray *array;
		gchar *var;
		const gchar *str;
		in_addr_t dest, gateway;
		guint32 metric, prefix;

		var = g_strdup_printf ("VPN_ROUTE_DEST_%d", i);
		str = g_getenv (var);
		g_free (var);
		if (!str || !*str)
			break;
		dest = inet_addr (str);

		var = g_strdup_printf ("VPN_ROUTE_MASK_%d", i);
		str = g_getenv (var);
		g_free (var);
		if (!str || !*str)
			prefix = 32;
		else
			prefix = nm_utils_ip4_netmask_to_prefix (inet_addr (str));

		var = g_strdup_printf ("VPN_ROUTE_GATEWAY_%d", i);
		str = g_getenv (var);
		g_free (var);
		if (!str || !*str)
			gateway = ouraddr;
		else
			gateway = inet_addr (str);

		var = g_strdup_printf ("VPN_ROUTE_METRIC_%d", i);
		str = g_getenv (var);
		g_free (var);
		if (!str || !*str)
			metric = 0;
		else
			metric = atol (str);

		array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 4);
		g_array_append_val (array, dest);
		g_array_append_val (array, prefix);
		g_array_append_val (array, gateway);
		g_array_append_val (array, metric);
		g_ptr_array_add (routes, array);
	}

	if (routes->len > 0) {
		value = g_new0 (GValue, 1);
		g_value_init (value, DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT);
		g_value_take_boxed (value, routes);
	} else {
		g_ptr_array_free (routes, TRUE);
	}

	return value;
}

static void
nm_ip_up (void *data, int arg)
{
	guint32 pppd_made_up_address = htonl (0x0a404040 + ifunit);
	ipcp_options opts = ipcp_gotoptions[0];
	ipcp_options peer_opts = ipcp_hisoptions[0];
	GHashTable *hash;
	GArray *array;
	GValue *val;
	const gchar *str;

	g_return_if_fail (DBUS_IS_G_PROXY (proxy));

	g_message ("nm-fortisslvpn-ppp-plugin: (%s): ip-up event", __func__);

	if (!opts.ouraddr) {
		g_warning ("nm-fortisslvpn-ppp-plugin: (%s): didn't receive an internal IP from pppd!", __func__);
		return;
	}

	hash = g_hash_table_new_full (g_str_hash, g_str_equal,
							NULL, value_destroy);

	g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, 
					 str_to_gvalue (ifname));

	str = g_getenv ("VPN_GATEWAY");
	if (str) {
		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY,
		                           uint_to_gvalue (inet_addr (str)));
	} else {
		g_warning ("nm-fortisslvpn-ppp-plugin: (%s): no external gateway!", __func__);
	}

	val = get_ip4_routes (opts.ouraddr);
	if (val)
		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, val);

	/* Prefer the peer options remote address first, _unless_ pppd made the
	 * address up, at which point prefer the local options remote address,
	 * and if that's not right, use the made-up address as a last resort.
	 */
	if (peer_opts.hisaddr && (peer_opts.hisaddr != pppd_made_up_address)) {
		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                     uint_to_gvalue (peer_opts.hisaddr));
	} else if (opts.hisaddr) {
		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                     uint_to_gvalue (opts.hisaddr));
	} else if (peer_opts.hisaddr == pppd_made_up_address) {
		/* As a last resort, use the made-up address */
		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                     uint_to_gvalue (peer_opts.hisaddr));
	}

	g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, 
					 uint_to_gvalue (opts.ouraddr));

	g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, uint_to_gvalue (32));

	if (opts.dnsaddr[0] || opts.dnsaddr[1]) {
		array = g_array_new (FALSE, FALSE, sizeof (guint32));

		if (opts.dnsaddr[0])
			g_array_append_val (array, opts.dnsaddr[0]);
		if (opts.dnsaddr[1])
			g_array_append_val (array, opts.dnsaddr[1]);

		val = g_slice_new0 (GValue);
		g_value_init (val, DBUS_TYPE_G_UINT_ARRAY);
		g_value_set_boxed (val, array);

		g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_DNS, val);
	}

	/* Default MTU to 1400, which is also what Windows XP/Vista use */
	g_hash_table_insert (hash, NM_VPN_PLUGIN_IP4_CONFIG_MTU, uint_to_gvalue (1400));

	g_message ("nm-fortisslvpn-ppp-plugin: (%s): sending Ip4Config to NetworkManager-fortisslvpn...", __func__);

	dbus_g_proxy_call_no_reply (proxy, "SetIp4Config",
	                            DBUS_TYPE_G_MAP_OF_VARIANT, hash, G_TYPE_INVALID,
	                            G_TYPE_INVALID);

	g_hash_table_destroy (hash);
}

static void
nm_exit_notify (void *data, int arg)
{
	g_return_if_fail (DBUS_IS_G_PROXY (proxy));

	g_message ("nm-fortisslvpn-ppp-plugin: (%s): cleaning up", __func__);

	g_object_unref (proxy);
	proxy = NULL;
}

int
plugin_init (void)
{
	DBusGConnection *bus;
	GError *err = NULL;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	g_message ("nm-fortisslvpn-ppp-plugin: (%s): initializing", __func__);

	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!bus) {
		g_warning ("nm-fortisslvpn-pppd-plugin: (%s): couldn't connect to system bus: (%d) %s",
		           __func__,
		           err ? err->code : -1,
		           err && err->message ? err->message : "(unknown)");
		g_error_free (err);
		return -1;
	}

	proxy = dbus_g_proxy_new_for_name (bus,
								NM_DBUS_SERVICE_FORTISSLVPN_PPP,
								NM_DBUS_PATH_FORTISSLVPN_PPP,
								NM_DBUS_INTERFACE_FORTISSLVPN_PPP);

	dbus_g_connection_unref (bus);

	add_notifier (&phasechange, nm_phasechange, NULL);
	add_notifier (&ip_up_notifier, nm_ip_up, NULL);
	add_notifier (&exitnotify, nm_exit_notify, proxy);

	return 0;
}
