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

#define _GNU_SOURCE
#include <string.h>

#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdbool.h>

#include <openssl/rand.h>

#include "json.h"

#include "hap_i.h"


//====================================================================


hap_service_t *
hap_service_create(void *opaque,
                   const char *type,
                   int num_characteristics,
                   hap_characteristic_t(*get)(void *opaque, int index),
                   int (*set)(void *opaque, int index, hap_value_t value))
{
  hap_service_t *hs = calloc(1, sizeof(hap_service_t) +
                             num_characteristics * sizeof(hap_value_type_t));
  hs->hs_opaque = opaque;
  hs->hs_type = strdup(type);
  hs->hs_num_characteristics = num_characteristics;
  hs->hs_characteristic_get = get;
  hs->hs_characteristic_set = set;

  return hs;
}



static int
add_service_on_thread(hap_accessory_t *ha, hap_msg_t *hm)
{
  const int aid = hm->hm_index;
  hap_service_t *hs = hm->hm_hs;

  const hap_service_t *last = TAILQ_LAST(&ha->ha_services, hap_service_queue);
  if(last == NULL) {
    hs->hs_iid = 1;
  } else {
    hs->hs_iid = last->hs_iid + last->hs_num_characteristics + 2;
    assert(aid == last->hs_aid || aid == last->hs_aid + 1);
  }

  hs->hs_aid = aid;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
  EVP_DigestUpdate(ctx, hs->hs_type, strlen(hs->hs_type));
  EVP_DigestUpdate(ctx, &hs->hs_aid, sizeof(hs->hs_aid));

  for(int i = 0; i < hs->hs_num_characteristics; i++) {
    hap_characteristic_t c = hs->hs_characteristic_get(hs->hs_opaque, i);
    EVP_DigestUpdate(ctx, c.type, strlen(c.type));
    EVP_DigestUpdate(ctx, &c.value.type, sizeof(c.value.type));
    EVP_DigestUpdate(ctx, &c.unit, sizeof(c.unit));
    EVP_DigestUpdate(ctx, &c.minValue, sizeof(c.minValue));
    EVP_DigestUpdate(ctx, &c.maxValue, sizeof(c.maxValue));
    EVP_DigestUpdate(ctx, &c.minStep, sizeof(c.minStep));
    hs->hs_formats[i] = c.value.type;
    free(c.storage);
  }
  EVP_DigestFinal_ex(ctx, hs->hs_config_digest, NULL);
  EVP_MD_CTX_free(ctx);

  TAILQ_INSERT_TAIL(&ha->ha_services, hs, hs_link);
  return 1;
}



void
hap_accessory_add_service(hap_accessory_t *ha, hap_service_t *hs, int aid)
{
  hs->hs_ha = ha;

  hap_msg_t *hm = calloc(1, sizeof(hap_msg_t));
  hm->hm_hs = hs;
  hm->hm_index = aid;
  hap_msg_enqueue(ha, hm, add_service_on_thread);
}


//====================================================================


static hap_characteristic_t
hap_make_string_ro(const char *type, const char *string)
{
  assert(string != NULL);
  return (hap_characteristic_t) {.type = type,
      .perms = HAP_PERM_PR,
      .value = { .type = HAP_STRING, .string = string }
  };
}

//====================================================================

static hap_characteristic_t
svc_accessory_information_get(void *opaque, int index)
{
  hap_accessory_t *ha = opaque;

  switch(index) {
  case 0: return hap_make_string_ro(HAP_CHARACTERISTIC_NAME,
                                    ha->ha_name);
  case 1: return hap_make_string_ro(HAP_CHARACTERISTIC_MANUFACTURER,
                                    ha->ha_manufacturer);
  case 2: return hap_make_string_ro(HAP_CHARACTERISTIC_SERIAL_NUMBER,
                                    ha->ha_id);
  case 3: return hap_make_string_ro(HAP_CHARACTERISTIC_MODEL,
                                    ha->ha_model);
  case 4: return hap_make_string_ro(HAP_CHARACTERISTIC_FIRMWARE_REVISION,
                                    ha->ha_version);
  case 5: return (hap_characteristic_t) {.type = HAP_CHARACTERISTIC_IDENTIFY,
      .perms = HAP_PERM_PW
  };
  default:
    return (hap_characteristic_t){};
  }
}


static hap_status_t
svc_accessory_information_set(void *opaque, int iid, hap_value_t value)
{
  return HAP_STATUS_OK;
}


static hap_service_t *
svc_accessory_information_create(hap_accessory_t *ha)
{
  return hap_service_create(ha, HAP_SERVICE_ACCESSORY_INFORMATION, 6,
                            svc_accessory_information_get,
                            svc_accessory_information_set);
}





//====================================================================

static hap_characteristic_t
svc_protocol_information_get(void *opaque, int index)
{
  return hap_make_string_ro(HAP_CHARACTERISTIC_VERSION, "01.01.00");
}

static hap_service_t *
svc_protocol_information_create(void)
{
  return hap_service_create(NULL,  HAP_SERVICE_PROTOCOL_INFORMATION, 1,
                            svc_protocol_information_get, NULL);
}


//====================================================================


#define HAP_CFG_ID            1
#define HAP_CFG_PRIVATE_KEY   2
#define HAP_CFG_PEER          3
#define HAP_CFG_CONFIG_HASH   4
#define HAP_CFG_CONFIG_NUMBER 5


static void
add_peer_from_config(hap_accessory_t *ha, const uint8_t *buf, int len)
{
  if(len < 34)
    return;
  hap_peer_t *hp = calloc(1, sizeof(hap_peer_t));

  memcpy(hp->hp_public_key, buf, 32);
  hp->hp_flags = buf[32];

  buf += 33;
  len -= 33;

  hp->hp_id = malloc(len + 1);
  memcpy(hp->hp_id, buf, len);
  hp->hp_id[len] = 0;
  LIST_INSERT_HEAD(&ha->ha_peers, hp, hp_link);
}


static void
hap_accessory_lts_parse(hap_accessory_t *ha, const uint8_t *buf, size_t size)
{
  while(size > 2) {
    const uint8_t type = buf[0];
    const uint8_t len  = buf[1];
    buf += 2;
    size -= 2;

    if(len > size)
      break;

    switch(type) {
    case HAP_CFG_PRIVATE_KEY:
      ha->ha_long_term_key =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, buf, len);
      break;
    case HAP_CFG_PEER:
      add_peer_from_config(ha, buf, len);
      break;
    case HAP_CFG_ID:
      ha->ha_id = strndup((const void *)buf, len);
      break;
    case HAP_CFG_CONFIG_HASH:
      if(len == sizeof(ha->ha_config_hash))
        memcpy(ha->ha_config_hash, buf, len);
      break;
    case HAP_CFG_CONFIG_NUMBER:
      if(len == sizeof(ha->ha_config_number))
        memcpy(&ha->ha_config_number, buf, len);
      break;
    }

    buf += len;
    size -= len;
  }
}


static void
hap_accessory_lts_load(hap_accessory_t *ha)
{
  int fd = open(ha->ha_storage_path, O_RDONLY);
  if(fd == -1)
    return;
  struct stat st;
  if(fstat(fd, &st)) {
    close(fd);
    return;
  }
  uint8_t *buf = malloc(st.st_size);
  if(buf == NULL) {
    close(fd);
    return;
  }

  if(read(fd, buf, st.st_size) != st.st_size) {
    free(buf);
    close(fd);
    return;
  }
  close(fd);

  hap_accessory_lts_parse(ha, buf, st.st_size);
  free(buf);
}

static void
lts_append_tlv(buf_t *buf, uint8_t type, uint8_t length, const void *value)
{
  buf_append_u8(buf, type);
  buf_append_u8(buf, length);
  buf_append(buf, value, length);
}





void
hap_accessory_lts_save(hap_accessory_t *ha)
{
  scoped_buf_t buf = {};

  uint8_t key[32];
  size_t key_size = sizeof(key);
  EVP_PKEY_get_raw_private_key(ha->ha_long_term_key, key, &key_size);

  lts_append_tlv(&buf, HAP_CFG_PRIVATE_KEY, sizeof(key), key);

  lts_append_tlv(&buf, HAP_CFG_ID, strlen(ha->ha_id), ha->ha_id);

  if(ha->ha_config_number) {
    lts_append_tlv(&buf, HAP_CFG_CONFIG_HASH, sizeof(ha->ha_config_hash),
                   ha->ha_config_hash);

    lts_append_tlv(&buf, HAP_CFG_CONFIG_NUMBER, sizeof(ha->ha_config_number),
                   &ha->ha_config_number);
  }

  const hap_peer_t *hp;
  LIST_FOREACH(hp, &ha->ha_peers, hp_link) {
    if(strlen(hp->hp_id) > 200)
      continue;
    buf_append_u8(&buf, HAP_CFG_PEER);
    buf_append_u8(&buf, sizeof(hp->hp_public_key) + 1 + strlen(hp->hp_id));
    buf_append(&buf, hp->hp_public_key, sizeof(hp->hp_public_key));
    buf_append_u8(&buf, hp->hp_flags);
    buf_append(&buf, hp->hp_id, strlen(hp->hp_id));
  }

  int fd = open(ha->ha_storage_path, O_WRONLY | O_TRUNC | O_CREAT, 0600);
  if(fd == -1) {
    hap_log(ha, NULL, LOG_WARNING, "Unable save state to %s -- %s",
            ha->ha_storage_path, strerror(errno));
    return;
  }

  if(write(fd, buf.data, buf.size) != buf.size) {
    hap_log(ha, NULL, LOG_WARNING, "Unable write state to %s",
            ha->ha_storage_path);
  }
  hap_log(ha, NULL, LOG_DEBUG, "Saved state to %s",
          ha->ha_storage_path);
  close(fd);
}


static void
value_buf_print(buf_t *b, hap_value_t value)
{
  switch(value.type) {
  case HAP_INTEGER:
    buf_printf(b, "\"value\":%d", value.integer);
    break;
  case HAP_FLOAT:
    buf_printf(b, "\"value\":%f", value.number);
    break;
  case HAP_BOOLEAN:
    buf_printf(b, "\"value\":%s", value.boolean ? "true" : "false");
    break;
  case HAP_STRING:
    buf_append_str(b, "\"value\":");
    buf_append_and_escape_jsonstr(b, value.string, 1);
    break;
  default:
    break;
  }
}



static void __attribute__((unused))
characteristic_to_json(hap_characteristic_t c, int aid, int iid,
                       const hap_connection_t *hc,
                       buf_t *output)
{
  buf_printf(output, "{\"type\":\"%s\",\"perms\":[", c.type);
  const char *sep = "";

  if(c.perms & HAP_PERM_PR) {
    buf_printf(output, "%s\"pr\"", sep); sep = ",";
  }
  if(c.perms & HAP_PERM_PW) {
    buf_printf(output, "%s\"pw\"", sep); sep = ",";
  }
  if(c.perms & HAP_PERM_EV) {
    buf_printf(output, "%s\"ev\"", sep); sep = ",";
  }
  buf_append_str(output, "],");
  if(iid)
    buf_printf(output, "\"iid\":%d,", iid);
  if(aid)
    buf_printf(output, "\"aid\":%d,", aid);

  const char *format = "bool";
  switch(c.value.type) {
  case HAP_INTEGER:
    format = "int";
    break;
  case HAP_STRING:
    format = "string";
    break;
  case HAP_FLOAT:
    format = "float";
    break;
  default:
    break;
  }

  if(c.minValue != c.maxValue) {
    buf_printf(output,
               "\"minValue\":%f,\"maxValue\":%f,",
               c.minValue, c.maxValue);
  }

  if(c.minStep) {
    buf_printf(output, "\"minStep\":%f,", c.minStep);
  }

  buf_printf(output, "%s\"format\":\"%s\",",
             hc != NULL &&
             intvec_find(&hc->hc_watched_iids, iid) != -1 ?
             "\"ev\":true," : "",
             format);

  value_buf_print(output, c.value);

  buf_append_str(output, "}");
}





int
hap_accessories(hap_connection_t *hc, enum http_method method,
                uint8_t *request_body, size_t request_body_len,
                const hap_query_args_t *qa)
{
  hap_accessory_t *ha = hc->hc_ha;
  hap_service_t *hs;
  scoped_buf_t json = {};
  int current_aid = 0;

  buf_append_str(&json, "{\"accessories\":[");
  TAILQ_FOREACH(hs, &ha->ha_services, hs_link) {

    if(current_aid != hs->hs_aid) {
      if(current_aid) {
        buf_append_str(&json, "},");
      }
      buf_printf(&json, "{\"aid\":%d,\"services\":[", hs->hs_aid);
      current_aid = hs->hs_aid;
    } else {
      buf_append_str(&json, ",");
    }

    buf_printf(&json,
               "{\"type\":\"%s\",\"iid\":%d,\"characteristics\":[",
               hs->hs_type, hs->hs_iid);

    for(int i = 0; i < hs->hs_num_characteristics; i++) {
      if(i)
        buf_append_str(&json, ",\n");
      const int iid = hs->hs_iid + 1 + i;
      hap_characteristic_t c = hs->hs_characteristic_get(hs->hs_opaque, i);
      characteristic_to_json(c, 0, iid, hc, &json);
      free(c.storage);
    }
    buf_append_str(&json, "]}");
  }
  buf_append_str(&json, "]}]}");
  return hap_http_send_reply(hc, 200, json.data, json.size,
                             "application/hap+json");
}




static void
hap_send_notify(hap_accessory_t *ha, int aid, int iid,
                hap_value_t value, hap_connection_t *skip)
{
  char headers[128];
  scoped_buf_t json = {};

  hap_connection_t *hc;
  LIST_FOREACH(hc, &ha->ha_connections, hc_link) {
    if(skip == hc || intvec_find(&hc->hc_watched_iids, iid) == -1)
      continue;

    if(json.size == 0) {

      buf_printf(&json,
                 "{\"characteristics\":[{\"aid\":%d,\"iid\":%d,",
                 aid, iid);
      value_buf_print(&json, value);
      buf_append_str(&json, "}]}");

      snprintf(headers, sizeof(headers),
               "EVENT/1.0 200 OK\r\n"
               "Content-Type: application/hap+json\r\n"
               "Content-Length: %zd\r\n"
               "\r\n", json.size);

    }
    hap_log(ha, hc, LOG_DEBUG, "Sending update event for aid:%d iid:%d",
            aid, iid);
    hap_http_send_data(hc, headers, strlen(headers));
    hap_http_send_data(hc, json.data, json.size);
  }
}


static int
hap_notify_on_thread(hap_accessory_t *ha, hap_msg_t *hm)
{
  hap_service_t *hs = hm->hm_hs;
  const int iid = hs->hs_iid + 1 + hm->hm_index;
  if(hm->hm_local_echo) {
    hs->hs_characteristic_set(hs->hs_opaque, hm->hm_index, hm->hm_value);
  }

  hap_send_notify(ha, hs->hs_aid, iid, hm->hm_value, NULL);
  return 0;
}


void
hap_service_notify(hap_service_t *hs, int index, hap_value_t value,
                   bool local_echo)
{
  hap_accessory_t *ha = hs->hs_ha;

  hap_msg_t *hm = calloc(1, sizeof(hap_msg_t));
  hm->hm_hs = hs;
  hm->hm_index = index;
  hm->hm_value = value;
  hm->hm_local_echo = local_echo;
  if(value.type == HAP_STRING) {
    hm->hm_data = strdup(value.string);
    hm->hm_value.string = hm->hm_data;
  }
  hap_msg_enqueue(ha, hm, hap_notify_on_thread);
}





static int
find_in_object(const char *json, struct json_token_t tokens[], int i,
               const char *name)
{
  if(tokens[i].type != JSON_OBJECT)
    return 0;

  for(i = tokens[i].child; i != 0; i = tokens[i].sibling) {
    if(json_string_equal(json + tokens[i].id,
                         tokens[i].id_length, name, strlen(name)))
      return i;
  }
  return 0;
}


static int
get_int(const char *json, struct json_token_t tokens[], int i, int defval)
{
  if(tokens[i].type == JSON_PRIMITIVE) {
    if(json[tokens[i].value] == 't') // true
      return 1;
    if(json[tokens[i].value] == 'f') // false
      return 0;
    return atoi(json + tokens[i].value);
  }
  return defval;

}

static int
get_named_int(const char *json, struct json_token_t tokens[], int i,
              const char *name, int defval)
{
  return get_int(json, tokens, find_in_object(json, tokens, i, name), defval);
}



int
hap_characteristics(hap_connection_t *hc, enum http_method method,
                    uint8_t *request_body, size_t request_body_len,
                    const hap_query_args_t *qa)
{
  hap_accessory_t *ha = hc->hc_ha;

  char errbuf[512];
  if(method == HTTP_PUT) {
    const char *req_json = (const char *)request_body;
    const int max_tokens = 256;
    struct json_token_t tokens[max_tokens];
    json_size_t num_tokens = json_parse(req_json, request_body_len,
                                        tokens, max_tokens);
    if(num_tokens == 0) {
      hap_log(ha, hc, LOG_WARNING, "Unable to parse JSON: %s", errbuf);
      return -1;
    }
    if(num_tokens > max_tokens) {
      hap_log(ha, hc, LOG_WARNING, "JSON request too big");
      return -1;
    }

    int i = find_in_object(req_json, tokens, 0, "characteristics");
    if(i == 0) {
      hap_log(ha, hc, LOG_WARNING,
              "JSON object does not have 'characteristics'");
      return -1;
    }

    int all_ok = 1;
    scoped_buf_t json = {};
    buf_append_str(&json, "{\"characteristics\":[");
    const char *sep = "";

    for(i = tokens[i].child; i != 0; i = tokens[i].sibling) {

      const int aid = get_named_int(req_json, tokens, i, "aid", 0);
      const int iid = get_named_int(req_json, tokens, i, "iid", 0);

      hap_service_t *hs;
      TAILQ_FOREACH(hs, &ha->ha_services, hs_link) {
        if(aid == hs->hs_aid &&
           iid >= hs->hs_iid + 1 &&
           iid <  hs->hs_iid + 1 + hs->hs_num_characteristics)
          break;
      }

      hap_status_t statusCode = HAP_STATUS_OK;

      if(hs == NULL) {
        hap_log(ha, hc, LOG_WARNING,
                "Attempt to write to non-existent aid:%d iid:%d",
                aid, iid);

        statusCode = HAP_STATUS_RESOURCE_DOES_NOT_EXIST;

      } else {
        int ev;
        int val = find_in_object(req_json, tokens, i, "value");

        if(val) {
          if(hs->hs_characteristic_set == NULL) {
            statusCode = HAP_STATUS_RESOURCE_IS_READ_ONLY;
          } else {

            const int idx = iid - hs->hs_iid - 1;
            assert(idx < hs->hs_num_characteristics);

            hap_value_t hv = {};

            switch(hs->hs_formats[idx]) {
            case HAP_INTEGER:
              hv.integer = get_int(req_json, tokens, val, 0);
              break;
            case HAP_BOOLEAN:
              hv.boolean = get_int(req_json, tokens, val, 0);
              break;
            case HAP_FLOAT:
              hv.number = get_int(req_json, tokens, val, 0);
              break;
            case HAP_STRING:
              break;
            case HAP_UNDEFINED:
              break;
            }

            statusCode = hs->hs_characteristic_set(hs->hs_opaque, idx, hv);
            if(statusCode == HAP_STATUS_OK) {
              hap_send_notify(ha, aid, iid, hv, hc);
            }
          }

        } else if((ev = find_in_object(req_json, tokens, i, "ev")) != 0) {

          int pos = intvec_find(&hc->hc_watched_iids, iid);
          const int on = get_int(req_json, tokens, ev, 0);
          if(on && pos == -1) {
            intvec_insert_sorted(&hc->hc_watched_iids, iid);
            hap_log(ha, hc, LOG_DEBUG, "Watching IID %d", iid);
          } else if(!on && pos != -1) {
            intvec_delete(&hc->hc_watched_iids, pos);
            hap_log(ha, hc, LOG_DEBUG, "Stopped watching IID %d", iid);
          }

        } else {
          statusCode = HAP_STATUS_INVALID_WRITE_REQ;
        }
      }

      all_ok &= !statusCode;

      buf_printf(&json, "%s{\"aid\":%d,\"iid\":%d,\"status\":%d}",
                 sep, aid, iid, statusCode);
    }

    if(all_ok)
      return hap_http_send_reply(hc, 204, NULL, 0, NULL);

    buf_append_str(&json, "]}");
    return hap_http_send_reply(hc, 207, json.data, json.size,
                               "application/hap+json");
  }

  if(method == HTTP_GET) {
    char *ids = hap_http_get_qa(qa, "id");
    if(ids == NULL)
      return hap_http_send_reply(hc, 400, NULL, 0, NULL);

    scoped_buf_t json = {};

    const int include_ev    = !!hap_http_get_qa(qa, "ev");
#if 0
    const int include_meta  = !!hap_http_get_qa(qa, "meta");
    const int include_perms = !!hap_http_get_qa(qa, "perms");
    const int include_type  = !!hap_http_get_qa(qa, "type");

    assert(include_meta  == 0);
    assert(include_perms == 0);
    assert(include_type  == 0);
#endif

    char *sp, *id;

    buf_append_str(&json, "{\"characteristics\":[");

    const char *sep = "";
    while((id = strtok_r(ids, ",", &sp)) != NULL) {
      ids = NULL;
      char *y = strchr(id, '.');
      if(y == NULL)
        continue;
      *y++ = 0;
      const int aid = atoi(id);
      const int iid = atoi(y);

      hap_service_t *hs;
      TAILQ_FOREACH(hs, &ha->ha_services, hs_link) {
        if(aid == hs->hs_aid &&
           iid >= hs->hs_iid + 1 &&
           iid <  hs->hs_iid + 1 + hs->hs_num_characteristics)
          break;
      }

      buf_append_str(&json, sep);
      sep = ",";

      hap_characteristic_t c =
        hs->hs_characteristic_get(hs->hs_opaque, iid - hs->hs_iid - 1);
      characteristic_to_json(c, aid, iid, include_ev ? hc : NULL, &json);
      free(c.storage);
    }
    buf_append_str(&json, "]}");
    return hap_http_send_reply(hc, 200, json.data, json.size,
                               "application/hap+json");

  }

  return hap_http_send_reply(hc, 405, NULL, 0, NULL);
}




/**
 *
 */
int
hap_get_random_bytes(void *out, size_t len)
{
  return !RAND_bytes(out, len);
}



hap_accessory_t *
hap_accessory_create(const char *name,
                     const char *password,
                     const char *storage_path,
                     hap_accessory_category_t category,
                     const char *manufacturer,
                     const char *model,
                     const char *version,
                     hap_log_callback_t *logcb,
                     void *opaque)
{
  int need_save = 0;

  // Must be in form XXX-XX-XXX
  if(strlen(password) != 10 || password[3] != '-' || password[6] != '-') {
    logcb(opaque, LOG_ERR, "Password not in form XXX-XX-XXX");
    return NULL;
  }

  hap_accessory_t *ha = calloc(1, sizeof(hap_accessory_t));
  TAILQ_INIT(&ha->ha_services);
  ha->ha_name = strdup(name);
  ha->ha_storage_path = strdup(storage_path);
  ha->ha_category = category;
  ha->ha_manufacturer = strdup(manufacturer);
  ha->ha_model = strdup(model);
  ha->ha_version = strdup(version ?: "0.1");
  ha->ha_password = strdup(password);

  hap_accessory_lts_load(ha);

  if(ha->ha_long_term_key == NULL) {
    ha->ha_long_term_key = EVP_PKEY_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &ha->ha_long_term_key);
    EVP_PKEY_CTX_free(pctx);
    need_save = 1;
  }


  if(ha->ha_id == NULL) {
    uint8_t b[6] = {};
    hap_get_random_bytes(b, sizeof(b));
    b[0] |= 0x2;
    b[0] &= ~0x1;
    ha->ha_id = fmt("%02x:%02x:%02x:%02x:%02x:%02x",
                    b[0], b[1], b[2], b[3], b[4], b[5]);
  }

  TAILQ_INIT(&ha->ha_msg_queue);
  pthread_mutex_init(&ha->ha_msg_mutex, NULL);

  hap_network_init(ha);

  hap_accessory_add_service(ha, svc_accessory_information_create(ha), 1);
  hap_accessory_add_service(ha, svc_protocol_information_create(), 1);

  if(need_save)
    hap_accessory_lts_save(ha);

  hap_log(ha, NULL, LOG_DEBUG, "Initialized as ID %s", ha->ha_id);

  return ha;
}




void
hap_accessory_start(hap_accessory_t *ha)
{
  hap_network_start(ha);
}





void
hap_accessory_destroy(hap_accessory_t *ha)
{
  hap_network_stop(ha);

  hap_peer_t *hp;
  while((hp = LIST_FIRST(&ha->ha_peers)) != NULL) {
    LIST_REMOVE(hp, hp_link);
    free(hp->hp_id);
    free(hp);
  }

  hap_service_t *hs;

  while((hs = TAILQ_FIRST(&ha->ha_services)) != NULL) {
    TAILQ_REMOVE(&ha->ha_services, hs, hs_link);
    free(hs->hs_type);
    free(hs);
  }

  EVP_PKEY_free(ha->ha_long_term_key);
  free(ha->ha_name);
  free(ha->ha_manufacturer);
  free(ha->ha_model);
  free(ha->ha_version);
  free(ha->ha_password);
  free(ha->ha_storage_path);
  free(ha->ha_id);

  free(ha);
}


void
hap_log(const hap_accessory_t *ha, const hap_connection_t *hc, int level,
        const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  scoped_char *msg = fmtv(format, ap);
  va_end(ap);

  scoped_char *line = fmt("%s%s%s", hc ? hc->hc_log_prefix : "",
                          hc ? ": " : "",
                          msg);

  if(ha->ha_logcb) {
    ha->ha_logcb(ha->ha_opaque, level, line);
  } else {
    fprintf(stderr, "%s\n", line);
  }
}


void
hap_freecharp(char **ptr)
{
  free(*ptr);
  *ptr = NULL;
}

char *
fmtv(const char *fmt, va_list ap)
{
  char *ret;
  if(vasprintf(&ret, fmt, ap) == -1)
    abort();
  return ret;
}

char *
fmt(const char *fmt, ...)
{
  va_list ap;
  char *ret;
  va_start(ap, fmt);
  ret = fmtv(fmt, ap);
  va_end(ap);
  return ret;
}
