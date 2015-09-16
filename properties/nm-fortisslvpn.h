/***************************************************************************
 * nm-fortisslvpn.h : GNOME UI dialogs for configuring fortisslvpn VPN connections
 *
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
 *
 **************************************************************************/

#ifndef _NM_FORTISSLVPN_H_
#define _NM_FORTISSLVPN_H_

#include <glib-object.h>

typedef enum
{
	FORTISSLVPN_PLUGIN_UI_ERROR_UNKNOWN = 0,
	FORTISSLVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
} FortisslvpnPluginUiError;

#define FORTISSLVPN_TYPE_PLUGIN_UI_ERROR (fortisslvpn_plugin_ui_error_get_type ()) 
GType fortisslvpn_plugin_ui_error_get_type (void);

#define FORTISSLVPN_PLUGIN_UI_ERROR (fortisslvpn_plugin_ui_error_quark ())
GQuark fortisslvpn_plugin_ui_error_quark (void);


#define FORTISSLVPN_TYPE_PLUGIN_UI            (fortisslvpn_plugin_ui_get_type ())
#define FORTISSLVPN_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), FORTISSLVPN_TYPE_PLUGIN_UI, FortisslvpnPluginUi))
#define FORTISSLVPN_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), FORTISSLVPN_TYPE_PLUGIN_UI, FortisslvpnPluginUiClass))
#define FORTISSLVPN_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FORTISSLVPN_TYPE_PLUGIN_UI))
#define FORTISSLVPN_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), FORTISSLVPN_TYPE_PLUGIN_UI))
#define FORTISSLVPN_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), FORTISSLVPN_TYPE_PLUGIN_UI, FortisslvpnPluginUiClass))

typedef struct _FortisslvpnPluginUi FortisslvpnPluginUi;
typedef struct _FortisslvpnPluginUiClass FortisslvpnPluginUiClass;

struct _FortisslvpnPluginUi {
	GObject parent;
};

struct _FortisslvpnPluginUiClass {
	GObjectClass parent;
};

GType fortisslvpn_plugin_ui_get_type (void);


#define FORTISSLVPN_TYPE_PLUGIN_UI_WIDGET            (fortisslvpn_plugin_ui_widget_get_type ())
#define FORTISSLVPN_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), FORTISSLVPN_TYPE_PLUGIN_UI_WIDGET, FortisslvpnPluginUiWidget))
#define FORTISSLVPN_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), FORTISSLVPN_TYPE_PLUGIN_UI_WIDGET, FortisslvpnPluginUiWidgetClass))
#define FORTISSLVPN_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FORTISSLVPN_TYPE_PLUGIN_UI_WIDGET))
#define FORTISSLVPN_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), FORTISSLVPN_TYPE_PLUGIN_UI_WIDGET))
#define FORTISSLVPN_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), FORTISSLVPN_TYPE_PLUGIN_UI_WIDGET, FortisslvpnPluginUiWidgetClass))

typedef struct _FortisslvpnPluginUiWidget FortisslvpnPluginUiWidget;
typedef struct _FortisslvpnPluginUiWidgetClass FortisslvpnPluginUiWidgetClass;

struct _FortisslvpnPluginUiWidget {
	GObject parent;
};

struct _FortisslvpnPluginUiWidgetClass {
	GObjectClass parent;
};

GType fortisslvpn_plugin_ui_widget_get_type (void);

#endif	/* _NM_FORTISSLVPN_H_ */

