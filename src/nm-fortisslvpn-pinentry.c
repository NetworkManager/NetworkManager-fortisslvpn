/* nm-fortisslvpn-pinentry - NetworkManager SSLVPN Password entry helper
 *
 * (C) 2019 Lubomir Rintel
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

#include "nm-default.h"

#include <glib/gstdio.h>
#include <gio/gunixinputstream.h>
#include <gio/gunixoutputstream.h>

#include "nm-fortisslvpn-pppd-service-dbus.h"
#include "nm-fortisslvpn-service.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

#define _NMLOG(level, ...) \
    G_STMT_START { \
         if (log_level >= (level)) { \
             g_printerr ("nm-fortisslvpn[%s] %-7s [pinentry-%ld] " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
                         log_prefix_token, \
                         nm_utils_syslog_to_str (level), \
                         (long) getpid () \
                         _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
         } \
    } G_STMT_END

#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)
#define _LOGE(...) _NMLOG(LOG_ERR, __VA_ARGS__)

int
main (int argc, char *argv[])
{
	gs_unref_object GInputStream *input_stream = g_unix_input_stream_new (STDIN_FILENO, FALSE);
	gs_unref_object GDataInputStream *data_input = g_data_input_stream_new (input_stream);
	gs_unref_object NMDBusFortisslvpnPpp *proxy = NULL;
	const char *bus_name;
	int log_level;
	const char *log_prefix_token;
	gs_free char *title = NULL;
	gs_free char *desc = NULL;
	gs_free char *prompt = NULL;
	gs_free char *hint = NULL;
	GError *error = NULL;
	char *line;

	bus_name = getenv ("NM_DBUS_SERVICE_FORTISSLVPN");
	if (!bus_name)
		bus_name = NM_DBUS_SERVICE_FORTISSLVPN;

	log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
	                                          10, 0, LOG_DEBUG,
	                                          LOG_NOTICE);
	log_prefix_token = getenv ("NM_VPN_LOG_PREFIX_TOKEN") ?: "???";

	proxy = nmdbus_fortisslvpn_ppp_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                                       G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                                       bus_name,
	                                                       NM_DBUS_PATH_FORTISSLVPN_PPP,
	                                                       NULL, &error);

	if (!proxy) {
		_LOGE ("couldn't create D-Bus proxy: %s", error->message);
		g_clear_error (&error);
		return 1;
	}


	g_print ("OK Pleased to meet you, but not as pleased as the acual pinentry program\n");

	while (1) {
		line = g_data_input_stream_read_line_utf8 (data_input, NULL, NULL, &error);
		if (error) {
			_LOGE ("Error: %s\n", error->message);
			g_clear_error (&error);
			return 1;
		}
		if (!line)
			return 0;

		if (g_str_has_prefix (line, "SETTITLE ")) {
			g_clear_pointer (&title, g_free);
			title = g_uri_unescape_string (strchr (line, ' ') + 1, NULL);
			g_print ("OK\n");
		} else if (g_str_has_prefix (line, "SETDESC ")) {
			g_clear_pointer (&desc, g_free);
			desc = g_uri_unescape_string (strchr (line, ' ') + 1, NULL);
			g_print ("OK\n");
		} else if (g_str_has_prefix (line, "SETPROMPT ")) {
			g_clear_pointer (&prompt, g_free);
			prompt = g_uri_unescape_string (strchr (line, ' ') + 1, NULL);
			g_print ("OK\n");
		} else if (g_str_has_prefix (line, "SETKEYINFO ")) {
			g_clear_pointer (&hint, g_free);
			hint = g_uri_unescape_string (strchr (line, ' ') + 1, NULL);
			g_print ("OK\n");
		} else if (strcmp (line, "GETPIN") == 0) {
			char *escaped;
			char *pin;

			if (nmdbus_fortisslvpn_ppp_call_get_pin_sync (proxy,
			                                              title ?: "",
			                                              desc ?: "",
			                                              prompt ?: "",
			                                              hint ?: "",
			                                              &pin, NULL, &error)) {
				escaped = g_uri_escape_string (pin, NULL, TRUE);
				g_free (pin);
				g_print ("D %s\nOK\n", escaped);
			} else {
				escaped = g_uri_escape_string (error->message, NULL, TRUE);
				g_print ("ERR %d %s\n", error->code, escaped);
				g_clear_error (&error);
			}
			g_free (escaped);
		} else {
			/* You're not my real pinentry program! */
			g_printerr (line);
			g_print ("ERR 666 Not understood\n");
		}
		g_free (line);
	}
}
