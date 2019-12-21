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
#include <stdlib.h>
#include <sys/param.h>

#include "hap.h"


//---------------------------------------------------------------------
// Simple lightbulb
//---------------------------------------------------------------------

typedef struct {
  void *opaque;
  hap_status_t (*set)(void *opaque, bool on);
  bool (*get)(void *opaque);
} lightbulb_t;


static hap_characteristic_t
lightbulb_get(void *opaque, int index)
{
  const lightbulb_t *lb = opaque;
  const bool on = lb->get(lb->opaque);

  return (hap_characteristic_t) {
    .type = HAP_CHARACTERISTIC_ON,
    .perms = HAP_PERM_PR | HAP_PERM_PW | HAP_PERM_EV,
    .value = {
      .type = HAP_BOOLEAN,
      .boolean = on
    }
  };
}

static int
lightbulb_set(void *opaque, int index, hap_value_t value)
{
  const lightbulb_t *lb = opaque;
  return lb->set(lb->opaque, value.boolean);
}


hap_service_t *
hap_light_builb_create(void *opaque,
                       bool (*get)(void *opaque),
                       hap_status_t (*set)(void *opaque, bool on))
{
  lightbulb_t *lb = calloc(1, sizeof(lightbulb_t));
  lb->opaque = opaque;
  lb->set = set;
  lb->get = get;
  return hap_service_create(lb, HAP_SERVICE_LIGHT_BULB, 1,
                            lightbulb_get, lightbulb_set);
}


//---------------------------------------------------------------------
// RGB light
//---------------------------------------------------------------------

typedef struct {
  void *opaque;
  hap_status_t (*set)(void *opaque, float r, float g, float b);

  bool on;
  int brightness;
  int hue;
  float saturation;
  float color_temp;

} rgblight_t;


static hap_characteristic_t
rgblight_get(void *opaque, int index)
{
  const rgblight_t *rgb = opaque;

  switch(index) {
  case 0:
    return (hap_characteristic_t) {
      .type = HAP_CHARACTERISTIC_ON,
      .perms = HAP_PERM_PR | HAP_PERM_PW | HAP_PERM_EV,
      .value = {
        .type = HAP_BOOLEAN,
        .boolean = rgb->on
      }
    };
  case 1:
    return (hap_characteristic_t) {
      .type = HAP_CHARACTERISTIC_BRIGHTNESS,
      .perms = HAP_PERM_PR | HAP_PERM_PW | HAP_PERM_EV,
      .value = {
        .type = HAP_INTEGER,
        .integer = rgb->brightness
      },
      .unit = HAP_UNIT_PERCENTAGE,
      .minValue = 0,
      .maxValue = 100,
      .minStep = 1,
    };
  case 2:
    return (hap_characteristic_t) {
      .type = HAP_CHARACTERISTIC_HUE,
      .perms = HAP_PERM_PR | HAP_PERM_PW | HAP_PERM_EV,
      .value = {
        .type = HAP_FLOAT,
        .integer = rgb->hue
      },
      .unit = HAP_UNIT_ARCDEGREES,
      .minValue = 0,
      .maxValue = 360,
      .minStep = 1,
    };
  case 3:
    return (hap_characteristic_t) {
      .type = HAP_CHARACTERISTIC_SATURATION,
      .perms = HAP_PERM_PR | HAP_PERM_PW | HAP_PERM_EV,
      .value = {
        .type = HAP_FLOAT,
        .integer = rgb->saturation
      },
      .unit = HAP_UNIT_PERCENTAGE,
      .minValue = 0,
      .maxValue = 100,
      .minStep = 1,
    };
  }
  return (hap_characteristic_t) {};
}

static int
rgblight_set(void *opaque, int index, hap_value_t value)
{
  rgblight_t *rgb = opaque;

  switch(index) {
  case 0:
    rgb->on = value.boolean;
    break;
  case 1:
    rgb->brightness = value.integer;
    break;
  case 2:
    rgb->hue = value.number;
    break;
  case 3:
    rgb->saturation = value.number;
    break;
  }

  const float S = rgb->saturation / 100.0f;
  const float V = rgb->brightness / 100.0f;
  const float kr = (300 + rgb->hue) % 360 / 60.0;
  const float kg = (180 + rgb->hue) % 360 / 60.0;
  const float kb = (60  + rgb->hue) % 360 / 60.0;
  const float r = V - V * S * MAX(MIN(MIN(kr, 4 - kr), 1), 0);
  const float g = V - V * S * MAX(MIN(MIN(kg, 4 - kg), 1), 0);
  const float b = V - V * S * MAX(MIN(MIN(kb, 4 - kb), 1), 0);
  return rgb->set(rgb->opaque, r, g, b);
}


hap_service_t *
hap_rgb_light_create(void *opaque,
                     bool (*get)(void *opaque),
                     hap_status_t (*set)(void *opaque,
                                         float r, float g, float b))
{
  rgblight_t *rgb = calloc(1, sizeof(rgblight_t));
  rgb->opaque = opaque;
  rgb->set = set;
  return hap_service_create(rgb, HAP_SERVICE_LIGHT_BULB, 4,
                            rgblight_get, rgblight_set);
}
