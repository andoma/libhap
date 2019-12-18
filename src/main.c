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

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include "hap.h"


// Example to create a light-bulb accessory

static void
logcb(void *opaque, int level, const char *message)
{
  fprintf(stderr, "%s\n", message);
}


static hap_status_t
lb_set(void *opaque, bool on)
{
  bool *status = opaque;
  *status = on;
  printf("Light builb is %s\n", on ? "ON" : "OFF");
  return HAP_STATUS_OK;
}



static bool
lb_get(void *opaque)
{
  bool *status = opaque;
  return *status;
}

static int light1;

/**
 *
 */
int
main(int argc, char **argv)
{
  hap_accessory_t *ha =
    hap_accessory_create("Hello World", "224-46-688",
                         "hap.cfg",
                         HAP_CAT_LIGHTING,
                         "Lonelycoder",
                         "Model1",
                         "1.0",
                         logcb, NULL);

  hap_service_t *hs;

  hs = hap_light_builb_create(&light1, lb_get, lb_set);
  hap_accessory_add_service(ha, hs, 1);

  hap_accessory_start(ha);

  printf("Running, press ^C to stop\n");

  pause();

  hap_accessory_destroy(ha);
  return 0;
}

