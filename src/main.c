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
#include <signal.h>
#include <string.h>

#include "hap.h"

#define ACCESSORY_MANUFACTURER "Lonelycoder"
#define ACCESSORY_MODEL        "Model1"
#define ACCESSORY_VERSION      "1.0"
#define ACCESSORY_PASSWORD     "224-46-688"

// Example to create a light-bulb accessory

static hap_status_t
lightbulb_set(void *opaque, bool on)
{
  printf("Light builb is %s\n", on ? "ON" : "OFF");
  return HAP_STATUS_OK;
}

static hap_accessory_t *
lightbulb_main(void)
{
  hap_accessory_t *ha =
    hap_accessory_create("Lightbulb", ACCESSORY_PASSWORD, "lightbuilb.cfg",
                         HAP_CAT_LIGHTING, ACCESSORY_MANUFACTURER,
                         ACCESSORY_MODEL, ACCESSORY_VERSION, NULL, NULL);

  hap_service_t *hs = hap_light_builb_create(NULL, lightbulb_set);
  hap_accessory_add_service(ha, hs, 1);
  return ha;
}


static hap_status_t
rgb_set(void *opaque, float r, float g, float b)
{
  char colorstr[64];
  snprintf(colorstr, sizeof(colorstr),
           ";2;%d;%d;%dm", (int)(r * 255), (int)(g * 255), (int)(b * 255));

  printf("\033[48%s      \033[0m "
         "R=%1.3f G=%1.3f B=%1.3f "
         "\033[48%s      \033[0m\n", colorstr, r, g, b, colorstr);
  return HAP_STATUS_OK;
}

static hap_accessory_t *
rgb_main(void)
{
  hap_accessory_t *ha =
    hap_accessory_create("RGB", ACCESSORY_PASSWORD, "rgb.cfg",
                         HAP_CAT_LIGHTING, ACCESSORY_MANUFACTURER,
                         ACCESSORY_MODEL, ACCESSORY_VERSION, NULL, NULL);

  hap_service_t *hs = hap_rgb_light_create(NULL, rgb_set);
  hap_accessory_add_service(ha, hs, 1);
  return ha;
}

static void
help(void)
{
  printf("Usage: hap <MODE>\n");
  printf(" MODE:\n");
  printf("   light-bulb      On/Off light bulb\n");
  printf("   rgb             RGB/Multicolor light\n");
}


static void
ctrlc(int sig)
{
  return;
}


/**
 *",
 */
int
main(int argc, char **argv)
{
  hap_accessory_t * ha;

  if(argc != 2) {
    help();
    return 1;
  }

  signal(SIGINT, ctrlc);

  if(!strcmp(argv[1], "light-bulb")) {
    ha = lightbulb_main();
  } else if(!strcmp(argv[1], "rgb")) {
    ha = rgb_main();
  } else {
    help();
    return 1;
  }

  hap_accessory_start(ha);
  pause();
  hap_accessory_destroy(ha);
  return 0;
}
