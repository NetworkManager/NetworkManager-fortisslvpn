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
 */

#include <string.h>
#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <glib.h>
#include <gio/gio.h>
#include <stdlib.h>

#include "nm-fortisslvpn-service.h"
#include "nm-ppp-status.h"

#include <nm-utils.h>

int plugin_init (void);

char pppd_version[] = VERSION;

static GDBusProxy *proxy = NULL;

static void
nm_phasechange (void *data, int arg)
{
	NMPPPStatus ppp_status = NM_PPP_STATUS_UNKNOWN;
	char *ppp_phase;

	g_return_if_fail (G_IS_DBUS_PROXY (proxy));

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
		g_dbus_proxy_call (proxy,
		                   "SetState",
		                   g_variant_new ("(u)", ppp_status),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   NULL,
		                   NULL, NULL);
	}
}

static GVariant *
get_ip4_routes (void)
{
	GVariantBuilder builder;
	GVariant *value;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));

	for (i = 0; i < 100; i++) {
		GVariantBuilder array;
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
			gateway = 0;
		else
			gateway = inet_addr (str);

		var = g_strdup_printf ("VPN_ROUTE_METRIC_%d", i);
		str = g_getenv (var);
		g_free (var);
		if (!str || !*str)
			metric = 0;
		else
			metric = atol (str);

		g_variant_builder_init (&array, G_VARIANT_TYPE ("au"));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (dest));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (prefix));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (gateway));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (metric));
		g_variant_builder_add_value (&builder, g_variant_builder_end (&array));
	}

	value = g_variant_builder_end (&builder);
	if (i > 1)
		return value;

	g_variant_unref (value);
	return NULL;
}

static void
nm_ip_up (void *data, int arg)
{
	guint32 pppd_made_up_address = htonl (0x0a404040 + ifunit);
	ipcp_options opts = ipcp_gotoptions[0];
	ipcp_options peer_opts = ipcp_hisoptions[0];
	GVariantBuilder builder;
	const gchar *str;
	GVariant *val;

	g_return_if_fail (G_IS_DBUS_PROXY (proxy));

	g_message ("nm-fortisslvpn-ppp-plugin: (%s): ip-up event", __func__);

	if (!opts.ouraddr) {
		g_warning ("nm-fortisslvpn-ppp-plugin: (%s): didn't receive an internal IP from pppd!", __func__);
		nm_phasechange (NULL, PHASE_DEAD);
		return;
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV,
	                       g_variant_new_string (ifname));

	str = g_getenv ("VPN_GATEWAY");
	if (str) {
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY,
		                       g_variant_new_uint32 (inet_addr (str)));
	} else {
		g_warning ("nm-fortisslvpn-ppp-plugin: (%s): no external gateway!", __func__);
	}

	val = get_ip4_routes ();
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, val);

	/* Prefer the peer options remote address first, _unless_ pppd made the
	 * address up, at which point prefer the local options remote address,
	 * and if that's not right, use the made-up address as a last resort.
	 */
	if (peer_opts.hisaddr && (peer_opts.hisaddr != pppd_made_up_address)) {
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                       g_variant_new_uint32 (peer_opts.hisaddr));
	} else if (opts.hisaddr) {
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                       g_variant_new_uint32 (opts.hisaddr));
	} else if (peer_opts.hisaddr == pppd_made_up_address) {
		/* As a last resort, use the made-up address */
		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
		                       g_variant_new_uint32 (peer_opts.hisaddr));
	}

	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS,
	                       g_variant_new_uint32 (opts.ouraddr));

	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,
	                       g_variant_new_uint32 (32));

	if (opts.dnsaddr[0] || opts.dnsaddr[1]) {
		guint32 dns[2];
		int len = 0;

		if (opts.dnsaddr[0])
			dns[len++] = opts.dnsaddr[0];
		if (opts.dnsaddr[1])
			dns[len++] = opts.dnsaddr[1];

		g_variant_builder_add (&builder, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_DNS,
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                  dns, len, sizeof (guint32)));
	}

	/* Default MTU to 1400, which is also what Windows XP/Vista use */
	g_variant_builder_add (&builder, "{sv}",
	                       NM_VPN_PLUGIN_IP4_CONFIG_MTU,
	                       g_variant_new_uint32 (1400));

	g_message ("nm-fortisslvpn-ppp-plugin: (%s): sending Ip4Config to NetworkManager-fortisslvpn...", __func__);

	g_dbus_proxy_call (proxy,
	                   "SetIp4Config",
	                   g_variant_new ("(a{sv})", &builder),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   NULL,
	                   NULL, NULL);
}

static void
nm_exit_notify (void *data, int arg)
{
	g_return_if_fail (G_IS_DBUS_PROXY (proxy));

	g_message ("nm-fortisslvpn-ppp-plugin: (%s): cleaning up", __func__);

	g_object_unref (proxy);
	proxy = NULL;
}

int
plugin_init (void)
{
	GError *err = NULL;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	g_message ("nm-fortisslvpn-ppp-plugin: (%s): initializing", __func__);

        proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
                                               G_DBUS_PROXY_FLAGS_NONE,
                                               NULL,
                                               NM_DBUS_SERVICE_FORTISSLVPN_PPP,
                                               NM_DBUS_PATH_FORTISSLVPN_PPP,
                                               NM_DBUS_INTERFACE_FORTISSLVPN_PPP,
                                               NULL, &err);
	if (!proxy) {
		g_warning ("nm-fortisslvpn-pppd-plugin: (%s): couldn't create D-Bus proxy: (%d) %s",
		           __func__,
		           err ? err->code : -1,
		           err && err->message ? err->message : "(unknown)");
		g_error_free (err);
		return -1;
	}

	add_notifier (&phasechange, nm_phasechange, NULL);
	add_notifier (&ip_up_notifier, nm_ip_up, NULL);
	add_notifier (&exitnotify, nm_exit_notify, proxy);

	return 0;
}
