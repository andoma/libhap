/*
 * MIT License
 *
 * Copyright (c) 2019 Andreas Smas
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

#include <stdbool.h>

#ifdef HAP_SHARED_OBJECT_BUILD
#define HAP_PUBLIC_API __attribute__((visibility("default")))
#else
#define HAP_PUBLIC_API
#endif

typedef enum {
  // Table 6-11: HAP Status Codes
  HAP_STATUS_OK                         = 0,
  HAP_STATUS_INSUFFICIENT_PRIVILEGES    = -70401,
  HAP_STATUS_UNABLE_TO_PERFORM          = -70402,
  HAP_STATUS_RESOURCE_IS_BUSY           = -70403,
  HAP_STATUS_RESOURCE_IS_READ_ONLY      = -70404,
  HAP_STATUS_RESOURCE_IS_WRITE_ONLY     = -70405,
  HAP_STATUS_NOTIFICATION_NOT_SUPPORTED = -70406,
  HAP_STATUS_OUT_OF_RESOURCES           = -70407,
  HAP_STATUS_OPERATION_TIMED_OUT        = -70408,
  HAP_STATUS_RESOURCE_DOES_NOT_EXIST    = -70409,
  HAP_STATUS_INVALID_WRITE_REQ          = -70410,
  HAP_STATUS_INSUFFICIENT_AUTHORIZATION = -70411,
} hap_status_t;




typedef enum {
  HAP_UNDEFINED = 0,
  HAP_INTEGER = 1,
  HAP_STRING = 2,
  HAP_BOOLEAN = 3,
  HAP_FLOAT = 4,
} hap_value_type_t;


typedef struct {
  hap_value_type_t type;
  union {
    const char *string;
    int integer;
    bool boolean;
    float number;
  };
} hap_value_t;

typedef enum {
  HAP_PERM_PR = 0x1,  // Paired Read
  HAP_PERM_PW = 0x2,  // Paired Write
  HAP_PERM_EV = 0x4,  // Events
} hap_perm_t;

typedef enum {
  HAP_UNIT_UNDEFINED = 0,
  HAP_UNIT_CELSIUS = 1,
  HAP_UNIT_PERCENTAGE = 2,
  HAP_UNIT_ARCDEGREES = 3,
  HAP_UNIT_LUX = 4,
  HAP_UNIT_SECONDS = 5,
} hap_unit_t;


typedef struct {
  const char *type;
  hap_value_t value;
  hap_perm_t perms;
  hap_unit_t unit;
  double minValue;
  double maxValue;
  double minStep;
  void *storage;
} hap_characteristic_t;


hap_characteristic_t hap_make_string_ro(const char *type, const char *string)
  HAP_PUBLIC_API;

typedef enum {
  HAP_CAT_OTHER = 1,
  HAP_CAT_BRIDGES = 2,
  HAP_CAT_FANS = 3,
  HAP_CAT_GARAGE_DOOR_OPENERS = 4,
  HAP_CAT_LIGHTING = 5,
  HAP_CAT_LOCKS = 6,
  HAP_CAT_OUTLETS = 7,
  HAP_CAT_SWITCHES = 8,
  HAP_CAT_THERMOSTATS = 9,
  HAP_CAT_SENSORS = 10,
  HAP_CAT_SECURITY_SYSTEMS = 11,
  HAP_CAT_DOORS = 12,
  HAP_CAT_WINDOWS = 13,
  HAP_CAT_WINDOW_COVERINGS = 14,
  HAP_CAT_PROGRAMMABLE_SWITCHES = 15,
  HAP_CAT_IP_CAMERAS = 17,
  HAP_CAT_VIDEO_DOORBELLS = 18,
  HAP_CAT_AIR_PURIFIERS = 19,
  HAP_CAT_HEATERS = 20,
  HAP_CAT_AIR_CONDITIONERS = 21,
  HAP_CAT_HUMIDIFIERS = 22,
  HAP_CAT_DEHUMIDIFIERS = 23,
  HAP_CAT_SPRINKLERS = 28,
  HAP_CAT_FAUCETS = 29,
  HAP_CAT_SHOWER_SYSTEMS = 30,
  HAP_CAT_REMOTES = 32,
} hap_accessory_category_t;


#define HAP_SERVICE_ACCESSORY_INFORMATION         "3E"
#define HAP_SERVICE_AIR_PURIFIER                  "BB"
#define HAP_SERVICE_AIR_QUALITY_SENSOR            "8D"
#define HAP_SERVICE_AUDIO_STREAM_MANAGEMENT       "127"
#define HAP_SERVICE_BATTERY                       "96"
#define HAP_SERVICE_CARBON_DIOXIDE_SENSOR         "97"
#define HAP_SERVICE_CARBON_MONOXIDE_SENSOR        "7F"
#define HAP_SERVICE_CONTACT_SENDOR                "80"
#define HAP_SERVICE_DOOR                          "81"
#define HAP_SERVICE_DOORBELL                      "121"
#define HAP_SERVICE_FAN                           "B7"
#define HAP_SERVICE_FAUCET                        "D7"
#define HAP_SERVICE_FILTER_MAINTENANCE            "BA"
#define HAP_SERVICE_GARAGE_DOOR_OPENER            "41"
#define HAP_SERVICE_PROTOCOL_INFORMATION          "A2"
#define HAP_SERVICE_HEATER_COOLER                 "BC"
#define HAP_SERVICE_HUMIDIFIER_DEHUMIDIFIER       "BD"
#define HAP_SERVICE_HUMIDITY_SENSOR               "82"
#define HAP_SERVICE_IRRIGATION_SYSTEM             "CF"
#define HAP_SERVICE_LEAK_SENSOR                   "83"
#define HAP_SERVICE_LIGHT_BULB                    "43"
#define HAP_SERVICE_LIGHT_SENSOR                  "84"
#define HAP_SERVICE_LOCK_MANAGEMENT               "44"
#define HAP_SERVICE_LOCK_MECHANISM                "45"
#define HAP_SERVICE_MOTION_SENSOR                 "85"
#define HAP_SERVICE_OCCUPANCY_SENSOR              "86"
#define HAP_SERVICE_OUTLET                        "47"
#define HAP_SERVICE_SECURITY_SYSTEM               "7E"
#define HAP_SERVICE_SERVICE_LABEL                 "CC"
#define HAP_SERVICE_SLAT                          "B9"
#define HAP_SERVICE_SMOKE_SENSOR                  "87"
#define HAP_SERVICE_STATELESS_PROGRAMMABLE_SWITCH "89"
#define HAP_SERVICE_SWITCH                        "49"
#define HAP_SERVICE_TARGET_CONTROL                "125"
#define HAP_SERVICE_TARGET_CONTROL_MANAGEMENT     "122"
#define HAP_SERVICE_TEMPERATURE_SENSOR            "8A"
#define HAP_SERVICE_THERMOSTAT                    "4A"
#define HAP_SERVICE_VAVLE                         "D0"
#define HAP_SERVICE_WINDOW                        "8B"
#define HAP_SERVICE_WINDOW_COVERING               "8C"


// This list is not yet complete
#define HAP_CHARACTERISTIC_ACCESSORY_FLAGS         "A6"
#define HAP_CHARACTERISTIC_ACTIVE                  "B0"
#define HAP_CHARACTERISTIC_ACTIVE_IDENTIFIER       "E7"
#define HAP_CHARACTERISTIC_ADMIN_ONLY_ACCESS       "1"
#define HAP_CHARACTERISTIC_AUDIO_FEEDBACK          "5"
#define HAP_CHARACTERISTIC_AIR_PARTICULATE_DENSITY "64"
#define HAP_CHARACTERISTIC_AIR_PARTICULATE_SIZE    "65"
#define HAP_CHARACTERISTIC_BRIGHTNESS              "8"
#define HAP_CHARACTERISTIC_FIRMWARE_REVISION       "52"
#define HAP_CHARACTERISTIC_HUE                     "13"
#define HAP_CHARACTERISTIC_IDENTIFY                "14"
#define HAP_CHARACTERISTIC_MANUFACTURER            "20"
#define HAP_CHARACTERISTIC_MODEL                   "21"
#define HAP_CHARACTERISTIC_NAME                    "23"
#define HAP_CHARACTERISTIC_ON                      "25"
#define HAP_CHARACTERISTIC_POSITION_TARGET         "7C"
#define HAP_CHARACTERISTIC_POSITION_CURRENT        "6D"
#define HAP_CHARACTERISTIC_POSITION_STATE          "72"
#define HAP_CHARACTERISTIC_SATURATION              "2F"
#define HAP_CHARACTERISTIC_SERIAL_NUMBER           "30"
#define HAP_CHARACTERISTIC_VERSION                 "37"


typedef struct hap_accessory hap_accessory_t;

typedef struct hap_service hap_service_t;

typedef void (hap_log_callback_t)(void *opaque, int level, const char *message);

typedef hap_characteristic_t (hap_get_callback_t)(void *opaque, int index);

typedef hap_status_t (hap_set_callback_t)(void *opaque, int index,
                                          hap_value_t value);

typedef void (hap_flush_callback_t)(void *opaque);

typedef void (hap_init_callback_t)(void *opaque);

typedef void (hap_fini_callback_t)(void *opaque);


/**
 * Create a new accessory.
 *
 * Once accessory has been created you should add services to it.
 *
 * Finally it should be started using hap_accessory_start()
 *
 * @name Name as displaye to the user
 * @password 8 digit numerical password. Must be in form "###-##-###"
 * @storage_path Full path to a file that contains long term settings.
 *               This include the peers we're paird to, our long-term
 *               private key, etc.
 * @category Pick from @hap_accessory_category_t above. Primarily affects
 *           which icon is shown to user when discovering device.
 * @manufaturer Only shown to user, no functional significance.
 * @model Only shown to user, no functional significance.
 * @version Must be in form "x.y" or "x.y.z" according to spec.
 * @logcb Callback for log messages. If NULL messages are writted to stderr.
 *        If you want to suppress all log, pass a dummy function.
 * @opaque Pointer passed as-is to @logcb
 */
hap_accessory_t *hap_accessory_create(const char *name,
                                      const char *password,
                                      const char *storage_path,
                                      hap_accessory_category_t category,
                                      const char *manufacturer,
                                      const char *model,
                                      const char *version,
                                      hap_log_callback_t *logcb,
                                      void *opaque) HAP_PUBLIC_API;

/**
 * Start accessory.
 *
 * This makes the accessory available on the network.
 */
void hap_accessory_start(hap_accessory_t *ha) HAP_PUBLIC_API;


/**
 * Create a new service.
 *
 * @opaque is passed to the @get and @set callbacks.
 * @type should be one of the HAP_SERVICE_ -defines.
 * @num_characteristics Number of characteristics for this service.
 *                      This simples services (such as ligh_bulb) only have
 *                      one characteristic (on, which can be in on or off state)
 *                      See specification for more details.
 * @get Invoked when libhap needs to read a characteristic.
 * @set Invoked when libhap needs to write a characteristic. Can be NULL.
 * @flush Invoked after one or more @set callbacks (originating from
 *        the same request) have finished. This is useful if you want
 *        avoid glitches for values that are derived from multiple
 *        characteristcs. For example HSV -> RGB conversion.
 * @init Invoked when libhap is about to announce the service. Can be NULL.
 * @fini Invoked when libhap is about to remove the service. Can be NULL.
 *
 * The callbacks are always invoked on the accessory's networking thread, thus
 * blocking for an extended period of time is not recommended.
 *
 * Note that you must add the service using hap_accessory_add_service() for
 * it to have any effect.
 */
hap_service_t *hap_service_create(void *opaque,
                                  const char *type,
                                  int num_characteristics,
                                  hap_get_callback_t *get,
                                  hap_set_callback_t *set,
                                  hap_flush_callback_t *flush,
                                  hap_init_callback_t *init,
                                  hap_fini_callback_t *fini) HAP_PUBLIC_API;


/**
 * Add a service to an accessory.
 *
 * If done after the accessory is started a new configuration-number
 * is generated the mDNS TXT record is updated so all peers will re-request
 * the (cached) config.
 *
 * Generally it's more efficient to add all services before the accessory
 * start. However, for more advanced accessories like a bridge, services
 * may come and go.
 */
void hap_accessory_add_service(hap_accessory_t *ha, hap_service_t *hs,
                               int aid) HAP_PUBLIC_API;

/**
 * Notify about update for a characteristic.
 *
 * This will push notification to all connected peers that have subscribed
 * for updates.
 *
 * For example, if you have a motion sensor and you have automation rules
 * configured that trigger on motion, you need to invoke this function
 * to update the status of the motion sensor.
 *
 * Can be called from any thread.
 *
 * @hs The service for which the characteristic is updated
 * @index Index of the characteristic (must be < num_characteristics when
 *        the service was created)
 * @value New value
 * @local_echo Iff true, the @set callback passed to hap_service_create()
 *             will be invoked as well. Note that the @set callback
 *             invokation is asynchronous with respect to this call.
 */
void hap_service_notify(hap_service_t *hs, int index,
                        hap_value_t value, bool local_echo) HAP_PUBLIC_API;


/**
 * Remove an accessory and free up all resources
 */
void hap_accessory_destroy(hap_accessory_t *ha) HAP_PUBLIC_API;


/**
 * Convenience functions for creating services.
 * (Unfortunately very sparse at the moment)
 */
hap_service_t *hap_light_builb_create(void *opaque,
                                      hap_status_t (*set)(void *opaque,
                                                          bool on))
  HAP_PUBLIC_API;

hap_service_t * hap_rgb_light_create(void *opaque,
                                     hap_status_t (*set)(void *opaque,
                                                         float r, float g,
                                                         float b))
  HAP_PUBLIC_API;
