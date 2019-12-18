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

#include "hap.h"

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
lightbulb_set(void *opaque, int iid, hap_value_t value)
{
  const lightbulb_t *lb = opaque;
  return lb->set(lb->opaque, value.boolean);
}


// Convenience
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
