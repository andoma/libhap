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
#include <stdlib.h>
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





typedef struct {
  char *name;
  char *manufacturer;
  char *sn;
  char *model;
  char *fw_revision;

} bridged_accessory_t;


static hap_characteristic_t
bridged_accessory_info_get(void *opaque, int index)
{
  bridged_accessory_t *ba = opaque;
  switch(index) {
  case 0: return hap_make_string_ro(HAP_CHARACTERISTIC_NAME,
                                    ba->name);
  case 1: return hap_make_string_ro(HAP_CHARACTERISTIC_MANUFACTURER,
                                    ba->manufacturer);
  case 2: return hap_make_string_ro(HAP_CHARACTERISTIC_SERIAL_NUMBER,
                                    ba->sn);
  case 3: return hap_make_string_ro(HAP_CHARACTERISTIC_MODEL,
                                    ba->model);
  case 4: return hap_make_string_ro(HAP_CHARACTERISTIC_FIRMWARE_REVISION,
                                    ba->fw_revision);
  case 5: return (hap_characteristic_t) {.type = HAP_CHARACTERISTIC_IDENTIFY,
      .perms = HAP_PERM_PW
  };
  default:
    return (hap_characteristic_t){};
  }
}


static void
bridged_accessory_info_fini(void *opaque)
{
  bridged_accessory_t *ba = opaque;
  free(ba->name);
  free(ba->manufacturer);
  free(ba->sn);
  free(ba->model);
  free(ba->fw_revision);
  free(ba);
}



static hap_service_t *
bridged_accessory_info_create(const char *name,
                              const char *manufacturer,
                              const char *sn,
                              const char *model,
                              const char *fw_revision)
{
  bridged_accessory_t *ba = calloc(1, sizeof(bridged_accessory_t));

  ba->name = strdup(name);
  ba->manufacturer = strdup(manufacturer);
  ba->sn = strdup(sn);
  ba->model = strdup(model);
  ba->fw_revision = strdup(fw_revision);

  return hap_service_create(ba, HAP_SERVICE_ACCESSORY_INFORMATION, 6,
                            bridged_accessory_info_get,
                            NULL, NULL, NULL,
                            bridged_accessory_info_fini);
}






static hap_accessory_t *
bridge_main(void)
{
  hap_accessory_t *ha =
    hap_accessory_create("Bridge", ACCESSORY_PASSWORD, "bridge.cfg",
                         HAP_CAT_BRIDGES, ACCESSORY_MANUFACTURER,
                         ACCESSORY_MODEL, ACCESSORY_VERSION, NULL, NULL);

  // Each accessory (identified by last argument to add service)
  // Needs to have its own accessory-info service
  // First the RGB light as #2

  hap_accessory_add_service(ha,
                            bridged_accessory_info_create("RGB",
                                                          "Lonelycoder",
                                                          "1234",
                                                          "test",
                                                          "1.0"),
                            2);

  // ... And its actual service

  hap_accessory_add_service(ha,
                            hap_rgb_light_create(NULL, rgb_set),
                            2);


  // #3 is a regular light bulb

  hap_accessory_add_service(ha,
                            bridged_accessory_info_create("Lightbulb",
                                                          "Lonelycoder",
                                                          "0000",
                                                          "test",
                                                          "1.0"),
                            3);

  // ... Lightbulbs actual service

  hap_accessory_add_service(ha,
                            hap_light_builb_create(NULL, lightbulb_set),
                            3);

  return ha;
}







static void
help(void)
{
  printf("Usage: hap <MODE>\n");
  printf(" MODE:\n");
  printf("   light-bulb      On/Off light bulb\n");
  printf("   rgb             RGB/Multicolor light\n");
  printf("   bridge          Multifunction bridge\n");
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
  } else if(!strcmp(argv[1], "bridge")) {
    ha = bridge_main();
  } else {
    help();
    return 1;
  }

  hap_accessory_start(ha);
  pause();
  hap_accessory_destroy(ha);
  return 0;
}
