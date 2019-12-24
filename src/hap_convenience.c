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

#include "hap_i.h"

//---------------------------------------------------------------------
// Simple lightbulb
//---------------------------------------------------------------------

typedef struct {
  void *opaque;
  hap_status_t (*set)(void *opaque, bool on);
  hap_service_t *hs;
} lightbulb_t;


static hap_characteristic_t
lightbulb_get(void *opaque, int index)
{
  const lightbulb_t *lb = opaque;
  bool *state = hap_service_state_recall(lb->hs, sizeof(bool));

  return (hap_characteristic_t) {
    .type = HAP_CHARACTERISTIC_ON,
    .perms = HAP_PERM_PR | HAP_PERM_PW | HAP_PERM_EV,
    .value = {
      .type = HAP_BOOLEAN,
      .boolean = *state
    }
  };
}

static hap_status_t
lightbulb_set(void *opaque, int index, hap_value_t value)
{
  const lightbulb_t *lb = opaque;
  bool *state = hap_service_state_recall(lb->hs, sizeof(bool));

  *state = value.boolean;
  hap_accessory_lts_save(lb->hs->hs_ha);
  return lb->set(lb->opaque, value.boolean);
}


static void
lightbulb_init(void *opaque)
{
  const lightbulb_t *lb = opaque;
  bool *state = hap_service_state_recall(lb->hs, sizeof(bool));
  lb->set(lb->opaque, *state);
}

static void
lightbulb_fini(void *opaque)
{
  lightbulb_t *lb = opaque;
  free(lb);
}


hap_service_t *
hap_light_builb_create(void *opaque,
                       hap_status_t (*set)(void *opaque, bool on))
{
  lightbulb_t *lb = calloc(1, sizeof(lightbulb_t));
  lb->opaque = opaque;
  lb->set = set;
  lb->hs = hap_service_create(lb, HAP_SERVICE_LIGHT_BULB, 1,
                              lightbulb_get, lightbulb_set, NULL,
                              lightbulb_init, lightbulb_fini);
  return lb->hs;
}


//---------------------------------------------------------------------
// RGB light
//---------------------------------------------------------------------


typedef struct {
  bool on;
  int brightness;
  int hue;
  float saturation;
} rgb_state_t;


typedef struct {
  void *opaque;
  hap_status_t (*set)(void *opaque, float r, float g, float b);
  hap_service_t *hs;
} rgblight_t;


static hap_characteristic_t
rgblight_get(void *opaque, int index)
{
  const rgblight_t *rgb = opaque;
  rgb_state_t *state = hap_service_state_recall(rgb->hs, sizeof(rgb_state_t));

  switch(index) {
  case 0:
    return (hap_characteristic_t) {
      .type = HAP_CHARACTERISTIC_ON,
      .perms = HAP_PERM_PR | HAP_PERM_PW | HAP_PERM_EV,
      .value = {
        .type = HAP_BOOLEAN,
        .boolean = state->on
      }
    };
  case 1:
    return (hap_characteristic_t) {
      .type = HAP_CHARACTERISTIC_BRIGHTNESS,
      .perms = HAP_PERM_PR | HAP_PERM_PW | HAP_PERM_EV,
      .value = {
        .type = HAP_INTEGER,
        .integer = state->brightness
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
        .number = state->hue
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
        .number = state->saturation
      },
      .unit = HAP_UNIT_PERCENTAGE,
      .minValue = 0,
      .maxValue = 100,
      .minStep = 1,
    };
  }
  return (hap_characteristic_t) {};
}

static hap_status_t
rgblight_update(const rgblight_t *rgb, const rgb_state_t *state)
{
  if(!state->on) {
    return rgb->set(rgb->opaque, 0, 0, 0);
  }
  const float S = state->saturation / 100.0f;
  const float V = state->brightness / 100.0f;
  const float kr = (300 + state->hue) % 360 / 60.0;
  const float kg = (180 + state->hue) % 360 / 60.0;
  const float kb = (60  + state->hue) % 360 / 60.0;
  const float r = V - V * S * MAX(MIN(MIN(kr, 4 - kr), 1), 0);
  const float g = V - V * S * MAX(MIN(MIN(kg, 4 - kg), 1), 0);
  const float b = V - V * S * MAX(MIN(MIN(kb, 4 - kb), 1), 0);
  return rgb->set(rgb->opaque, r, g, b);

}


static int
rgblight_set(void *opaque, int index, hap_value_t value)
{
  rgblight_t *rgb = opaque;
  rgb_state_t *state = hap_service_state_recall(rgb->hs, sizeof(rgb_state_t));

  switch(index) {
  case 0:
    state->on = value.boolean;
    break;
  case 1:
    state->brightness = value.integer;
    break;
  case 2:
    state->hue = value.number;
    break;
  case 3:
    state->saturation = value.number;
    break;
  }

  return 0;
}

static void
rgblight_flush(void *opaque)
{
  rgblight_t *rgb = opaque;
  rgb_state_t *state = hap_service_state_recall(rgb->hs, sizeof(rgb_state_t));
  hap_accessory_lts_save(rgb->hs->hs_ha);
  rgblight_update(rgb, state);
}

static void
rgblight_init(void *opaque)
{
  rgblight_t *rgb = opaque;
  rgb_state_t *state = hap_service_state_recall(rgb->hs, sizeof(rgb_state_t));
  rgblight_update(rgb, state);
}

static void
rgblight_fini(void *opaque)
{
  rgblight_t *rgb = opaque;
  free(rgb);
}



hap_service_t *
hap_rgb_light_create(void *opaque,
                     hap_status_t (*set)(void *opaque,
                                         float r, float g, float b))
{
  rgblight_t *rgb = calloc(1, sizeof(rgblight_t));
  rgb->opaque = opaque;
  rgb->set = set;
  rgb->hs = hap_service_create(rgb, HAP_SERVICE_LIGHT_BULB, 4,
                               rgblight_get, rgblight_set, rgblight_flush,
                               rgblight_init, rgblight_fini);
  return rgb->hs;
}
