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

#ifndef __NM_FORTISSLVPN_PROPERTIES_H__
#define __NM_FORTISSLVPN_PROPERTIES_H__

#include "nm-default.h"

gboolean nm_fortisslvpn_properties_validate (NMSettingVpn *s_vpn, GError **error);

gboolean nm_fortisslvpn_properties_validate_secrets (NMSettingVpn *s_vpn, GError **error);

#endif /* __NM_FORTISSLVPN_PROPERTIES_H__ */
