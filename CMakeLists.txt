    cmake_minimum_required(VERSION 3.15)

    project(keepclient C)

    include_directories(
            ${PROJECT_SOURCE_DIR}/inc
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/appcore-agent
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/appcore-watch
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/appfw
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/badge
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/base
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/cairo
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/ckm
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/content
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/context-manager
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/dbus-1.0
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/device
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/dlog
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/ecore-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/e_dbus-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/edje-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/eet-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/efl-extension
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/efreet-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/eina-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/eina-1/eina
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/eio-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/elementary-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/embryo-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/ethumb-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/evas-1
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/ewebkit2-0
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/fontconfig
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/freetype2
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/gio-unix-2.0
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/glib-2.0
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/json-glib-1.0
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/json-glib-1.0/json-glib
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/libxml2
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/location
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/media
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/media-content
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/messaging
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/minizip
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/network
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/notification
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/sensor
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/storage
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/system
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/telephony
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/ui
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/widget_service
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/include/widget_viewer_evas
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/lib/dbus-1.0/include
            ~/tizen-studio/platforms/tizen-2.3.1/wearable/rootstraps/wearable-2.3.1-device.core/usr/lib/glib-2.0/include
    )

    add_executable(keepclient
            inc/keepclient.h src/keepclient.c
            inc/base64.h src/base64.c
            inc/https.h src/https.c
            inc/gpsoauth.h src/gpsoauth.c
            inc/gkeep.h src/gkeep.c
            inc/main_view.h src/view/main_view.c
            inc/main_event_handler.h src/event_handler/main_event_handler.c
    )
