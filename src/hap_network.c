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

#include <string.h>
#include <sys/param.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>

#include "hap_i.h"

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/alternative.h>
#include <avahi-client/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>

static void
entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state,
		     void *userdata)
{
  char *n;
  hap_accessory_t *ha = userdata;
  switch(state) {
  case AVAHI_ENTRY_GROUP_ESTABLISHED:
    hap_log(ha, NULL, LOG_INFO, "mDNS Service %s successfully established",
            ha->ha_name);
    break;

  case AVAHI_ENTRY_GROUP_COLLISION:
    n = avahi_alternative_service_name(ha->ha_name);
    free(ha->ha_name);
    ha->ha_name = n;

    hap_log(ha, NULL, LOG_INFO,
            "mDNS service name collision, renaming service to: %s",
            ha->ha_name);

    hap_mdns_update(ha);
    break;

  case AVAHI_ENTRY_GROUP_FAILURE:
    hap_log(ha, NULL, LOG_INFO, "mDNS group failure: %s",
            avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
    break;

  case AVAHI_ENTRY_GROUP_UNCOMMITED:
  case AVAHI_ENTRY_GROUP_REGISTERING:
    break;
  }
}



void
hap_mdns_update(hap_accessory_t *ha)
{
  if(ha->ha_group == NULL)
    return;

  int ret;
  char txt_id[64];
  snprintf(txt_id, sizeof(txt_id), "id=%s", ha->ha_id);

  char txt_md[128];
  snprintf(txt_md, sizeof(txt_md), "md=%s", ha->ha_model);

  char txt_ci[32];
  snprintf(txt_ci, sizeof(txt_ci), "ci=%d", ha->ha_category);

  char txt_sf[32];
  snprintf(txt_sf, sizeof(txt_sf), "sf=%d",
           LIST_FIRST(&ha->ha_peers) ? 0 : 1);

  char txt_csharp[32];
  snprintf(txt_csharp, sizeof(txt_csharp), "c#=%d",
           ha->ha_config_number);

  if(avahi_entry_group_is_empty(ha->ha_group)) {

    if((ret = avahi_entry_group_add_service(ha->ha_group, AVAHI_IF_UNSPEC,
                                            AVAHI_PROTO_UNSPEC, 0, ha->ha_name,
                                            "_hap._tcp", NULL, NULL,
                                            ha->ha_http_listen_port,
                                            "s#=1",    // Must be 1
                                            txt_ci,
                                            txt_sf,
                                            "pv=1.1",  // version, must be 1.1
                                            txt_md,
                                            txt_id,
                                            "ff=0",    // Must be 0
                                            txt_csharp,
                                            NULL)) < 0) {

      if(ret == AVAHI_ERR_COLLISION) {
        char *n = avahi_alternative_service_name(ha->ha_name);
        avahi_free(ha->ha_name);
        ha->ha_name = n;

        hap_log(ha, NULL, LOG_INFO,
                "mDNS service name collision, renaming service to: %s",
                ha->ha_name);

        avahi_entry_group_reset(ha->ha_group);

        hap_mdns_update(ha);
        return;
      }

      hap_log(ha, NULL, LOG_ERR,
              "mDNS failed to add _hap._tcp service: %s",
              avahi_strerror(ret));
      return;
    }

    if((ret = avahi_entry_group_commit(ha->ha_group)) < 0) {
      hap_log(ha, NULL, LOG_ERR, "mDNS failed to commit entry group: %s",
            avahi_strerror(ret));
      return;
    }
  } else {
    avahi_entry_group_update_service_txt(ha->ha_group, AVAHI_IF_UNSPEC,
                                         AVAHI_PROTO_UNSPEC, 0,
                                         ha->ha_name,
                                         "_hap._tcp", NULL,
                                         "s#=1",    // Must be 1
                                         txt_ci,
                                         txt_sf,
                                         "pv=1.1",// version, must be 1.1
                                         txt_md,
                                         txt_id,
                                         "ff=0",    // Must be 0
                                         txt_csharp,
                                         NULL);
  }
}


/**
 *
 */
static void
client_callback(AvahiClient *c, AvahiClientState state, void *userdata)
{
  hap_accessory_t *ha = userdata;

  switch(state) {
  case AVAHI_CLIENT_S_RUNNING:
    ha->ha_group = avahi_entry_group_new(c, entry_group_callback, userdata);
    hap_mdns_update(ha);
    break;

  case AVAHI_CLIENT_FAILURE:
    hap_log(ha, NULL, LOG_ERR, "mDNS client failure: %s",
          avahi_strerror(avahi_client_errno(c)));
    break;

  case AVAHI_CLIENT_S_COLLISION:
  case AVAHI_CLIENT_S_REGISTERING:
    if(ha->ha_group)
      avahi_entry_group_reset(ha->ha_group);
    break;
  case AVAHI_CLIENT_CONNECTING:
    break;
  }
}





static int
hap_prepare(hap_connection_t *hc, enum http_method method,
            uint8_t *request_body, size_t request_body_len,
            const hap_query_args_t *qa)
{
  const char *resp = "{\"status\":0}";
  return hap_http_send_reply(hc, 200, resp, strlen(resp),
                             "application/hap+json");
}

const static struct {
  const char *path;
  int (*fn)(hap_connection_t *hc, enum http_method method,
            uint8_t *request_body, size_t request_body_len,
            const hap_query_args_t *qas);
  int must_be_authed;
} http_paths[] = {
  {"/pair-setup",      hap_pair_setup, 0 },
  {"/pair-verify",     hap_pair_verify, 0 },
  {"/pairings",        hap_pairings, 1 },
  {"/accessories",     hap_accessories, 1 },
  {"/characteristics", hap_characteristics, 1 },
  {"/prepare",         hap_prepare, 1 },
};

int
hap_http_send_data(hap_connection_t *hc, const void *data, size_t len)
{
  uint8_t buf[2 + 1024 + 16]; // 2 byte header + Max frame + authtag

  EVP_CIPHER_CTX *ctx = hc->hc_cipher_context;

  if(ctx == NULL)
    return write(hc->hc_fd, data, len) != len;

  EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
  while(len) {
    int fs = MIN(len, 1024);

    uint8_t nonce[12] = {0,0,0,0, hc->hc_encrypted_frames,
                         hc->hc_encrypted_frames >> 8,
                         hc->hc_encrypted_frames >> 16,
                         hc->hc_encrypted_frames >> 24, 0,0,0,0};

    hc->hc_encrypted_frames++;
    int outlen = 0;
    buf[0] = fs;
    buf[1] = fs >> 8;

    EVP_EncryptInit_ex(ctx, NULL, NULL, hc->hc_SendKey, nonce);

    if(EVP_EncryptUpdate(ctx, NULL, &outlen, buf, 2) != 1)
      return -1;
    if(EVP_EncryptUpdate(ctx, buf + 2, &outlen, data, fs) != 1)
      return -1;
    if(EVP_EncryptFinal_ex(ctx, buf + 2 + outlen, &outlen) != 1)
      return -1;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                        buf + 2 + fs);

    if(write(hc->hc_fd, buf, 2 + fs + 16) != 2 + fs + 16)
      return -1;

    len -= fs;
    data += fs;
  }
  return 0;
}



int
hap_http_send_reply(hap_connection_t *hc, int status, const void *body,
                    size_t content_length, const char *content_type)
{
  char buf[128];

  if(status == 204) {
    snprintf(buf, sizeof(buf),
             "HTTP/1.1 %d %s\r\n"
             "\r\n",
             status, http_status_str(status));
  } else {
    snprintf(buf, sizeof(buf),
             "HTTP/1.1 %d %s\r\n"
             "%s%s%s"
             "Content-Length: %zd\r\n"
             "\r\n",
             status, http_status_str(status),
             content_type ? "Content-Type: " : "",
             content_type ?: "",
             content_type ? "\r\n" : "",
             content_length);
  }

  if(hap_http_send_data(hc, buf, strlen(buf)))
    return -1;

  return body ? hap_http_send_data(hc, body, content_length) : 0;
}


static int
on_message_begin(http_parser *p)
{
  hap_connection_t *hc = p->data;
  buf_reset(&hc->hc_path);
  buf_reset(&hc->hc_body);
  return 0;
}

static int
on_url(http_parser *p, const char *at, size_t length)
{
  hap_connection_t *hc = p->data;
  if(hc->hc_path.size > 1024)
    return 1;
  buf_append(&hc->hc_path, at, length);
  return 0;
}

static int
on_body(http_parser *p, const char *at, size_t length)
{
  hap_connection_t *hc = p->data;
  if(hc->hc_path.size > 65536)
    return 1;
  buf_append(&hc->hc_body, at, length);
  return 0;
}



struct hap_query_args {
  char *key;
  char *value;
};


char *
hap_http_get_qa(const hap_query_args_t *qa, const char *key)
{
  while(qa->key) {
    if(!strcmp(qa->key, key))
      return qa->value;
    qa++;
  }
  return NULL;
}


static int
on_message_complete(http_parser *p)
{
  hap_connection_t *hc = p->data;
  char *path = hc->hc_path.data;

  hap_log(hc->hc_ha, hc, LOG_DEBUG, "%s %s",
        http_method_str(p->method), path);

  struct hap_query_args qas[16];
  int num_query_args = 0;

  char *qa = strchr(path, '?');
  if(qa != NULL) {
    *qa++ = 0;
    char *sp, *key;

    while(num_query_args < ARRAYSIZE(qas) - 1 &&
          (key = strtok_r(qa, "&", &sp)) != NULL) {
      qa = NULL;
      qas[num_query_args].key = key;
      char *value = key + strcspn(key, "=");
      if(*value == '=') {
        *value++ = 0;
      }
      qas[num_query_args].value = value;
      num_query_args++;
    }
  }
  qas[num_query_args].key = NULL;

  for(size_t i = 0; i < ARRAYSIZE(http_paths); i++) {
    if(!strcmp(path, http_paths[i].path)) {

      if(http_paths[i].must_be_authed && !hc->hc_cipher_context) {
        return hap_http_send_reply(hc, 470, NULL, 0, NULL);
      }

      return http_paths[i].fn(hc, p->method, hc->hc_body.data,
                              hc->hc_body.size, qas);
    }
  }
  hap_log(hc->hc_ha, hc, LOG_NOTICE, "Path %s not found", path);
  return hap_http_send_reply(hc, 404, NULL, 0, NULL);
}


static const http_parser_settings hap_http_parser_settings = {
  .on_message_begin    = on_message_begin,
  .on_url              = on_url,
  .on_body             = on_body,
  .on_message_complete = on_message_complete,
};




static int
http_connection_decrypt_frame(hap_connection_t *hc,
                              const uint8_t *frame, int frame_size)
{
  uint8_t buf[frame_size];

  EVP_DecryptInit_ex(hc->hc_cipher_context, EVP_chacha20_poly1305(),
                     NULL, NULL, NULL);

  uint8_t n[12] = {0,0,0,0, hc->hc_decrypted_frames,
                   hc->hc_decrypted_frames >> 8,
                   hc->hc_decrypted_frames >> 16,
                   hc->hc_decrypted_frames >> 24, 0,0,0,0};
  hc->hc_decrypted_frames++;
  EVP_CIPHER_CTX_ctrl(hc->hc_cipher_context, EVP_CTRL_AEAD_SET_TAG, 16,
                      (uint8_t *)frame + 2 + frame_size);

  EVP_DecryptInit_ex(hc->hc_cipher_context, NULL, NULL, hc->hc_RecvKey, n);

  int outlen = 0;
  int rv = EVP_DecryptUpdate(hc->hc_cipher_context, NULL, &outlen, frame, 2);
  if(rv != 1)
    return -1;

  rv = EVP_DecryptUpdate(hc->hc_cipher_context, buf, &outlen,
                         frame + 2, frame_size);
  if(rv != 1)
    return -1;

  rv = EVP_DecryptFinal_ex(hc->hc_cipher_context, (uint8_t *)buf, &outlen);
  if(rv != 1)
    return -1;

  EVP_CIPHER_CTX_reset(hc->hc_cipher_context);

  const void *s = buf;
  int r = frame_size;

  //  hexdump("HTTP INPUT", s, r);

  while(!hc->hc_parser.http_errno && r > 0) {
    size_t x = http_parser_execute(&hc->hc_parser, &hap_http_parser_settings,
                                   s, r);
    s += x;
    r -= x;
  }

  return 0;
}



static void
http_delete_connection(hap_connection_t *hc)
{
  hap_accessory_t *ha = hc->hc_ha;

  hap_log(hc->hc_ha, hc, LOG_DEBUG, "Disconnected");

  if(hc->hc_psc != NULL)
    hap_pair_setup_ctx_free(hc->hc_psc);
  ha->ha_ap->watch_free(hc->hc_watch);
  close(hc->hc_fd);

  buf_free(&hc->hc_path);
  buf_free(&hc->hc_body);
  buf_free(&hc->hc_encrypted);

  if(hc->hc_cipher_context != NULL)
    EVP_CIPHER_CTX_free(hc->hc_cipher_context);

  LIST_REMOVE(hc, hc_link);
  intvec_reset(&hc->hc_watched_iids);
  free(hc->hc_log_prefix);
  free(hc);

}


static void
http_input(AvahiWatch *w, int fd, AvahiWatchEvent event, void *userdata)
{
  hap_connection_t *hc = userdata;
  char buf[1024];

  int r = read(hc->hc_fd, buf, sizeof(buf));
  if(r < 1) {
    http_delete_connection(hc);
    return;
  }

  if(hc->hc_cipher_context) {
    buf_append(&hc->hc_encrypted, buf, r);

    while(hc->hc_encrypted.size >= 2) {
      const uint8_t *u8 = hc->hc_encrypted.data;
      int frame_size = u8[0] | (u8[1] << 8);

      if(2 + 16 + frame_size >= hc->hc_encrypted.size) {
        // We have a complete frame
        if(http_connection_decrypt_frame(hc, hc->hc_encrypted.data,
                                         frame_size)) {

          hap_log(hc->hc_ha, hc, LOG_WARNING, "Stream decryption failed");
          http_delete_connection(hc);
          return;
        }
        buf_pop(&hc->hc_encrypted, 2 + 16 + frame_size);
      }
    }

  } else {
    const char *s = buf;

    while(!hc->hc_parser.http_errno && r > 0) {
      size_t x = http_parser_execute(&hc->hc_parser,
                                     &hap_http_parser_settings,
                                     s, r);
      s += x;
      r -= x;
    }
  }
  if(hc->hc_parser.http_errno) {
    hap_log(hc->hc_ha, hc, LOG_WARNING, "HTTP parser error %s",
          http_errno_name(hc->hc_parser.http_errno));
    http_delete_connection(hc);
    return;
  }
}

static void
http_new_connection(AvahiWatch *w, int listen_fd, AvahiWatchEvent event,
                    void *userdata)
{
  hap_accessory_t *ha = userdata;
  struct sockaddr_in sin;
  socklen_t slen = sizeof(sin);

  int fd = accept(listen_fd, (struct sockaddr *)&sin, &slen);
  if(fd == -1)
    return;

  hap_connection_t *hc = calloc(1, sizeof(hap_connection_t));
  LIST_INSERT_HEAD(&ha->ha_connections, hc, hc_link);
  hc->hc_ha = ha;
  hc->hc_fd = fd;
  hc->hc_log_prefix = strdup(inet_ntoa(sin.sin_addr));
  hc->hc_parser.data = hc;
  http_parser_init(&hc->hc_parser, HTTP_REQUEST);

  hc->hc_remote_addr = sin;
  hap_log(hc->hc_ha, hc, LOG_DEBUG, "Connected");

  hc->hc_watch = ha->ha_ap->watch_new(ha->ha_ap, fd, AVAHI_WATCH_IN,
                                      http_input, hc);
}


//====================================================================


static int
hap_check_config_hash(hap_accessory_t *ha)
{
  uint8_t digest[20];
  const hap_service_t *hs;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
  TAILQ_FOREACH(hs, &ha->ha_services, hs_link) {
    EVP_DigestUpdate(ctx, hs->hs_config_digest, sizeof(hs->hs_config_digest));
  }
  EVP_DigestFinal_ex(ctx, digest, NULL);
  EVP_MD_CTX_free(ctx);

  if(!memcmp(digest, ha->ha_config_hash, sizeof(ha->ha_config_hash)))
    return 0;

  memcpy(ha->ha_config_hash, digest, sizeof(ha->ha_config_hash));
  ha->ha_config_number++;
  if(ha->ha_config_number == 0)
    ha->ha_config_number = 1;

  hap_log(ha, NULL, LOG_DEBUG, "Config number updated to %d",
          ha->ha_config_number);
  return 1;
}




static int
dispatch_message(hap_accessory_t *ha)
{
  hap_msg_t *hm = TAILQ_FIRST(&ha->ha_msg_queue);
  pthread_mutex_lock(&ha->ha_msg_mutex);
  if(hm != NULL)
    TAILQ_REMOVE(&ha->ha_msg_queue, hm, hm_link);
  pthread_mutex_unlock(&ha->ha_msg_mutex);
  if(hm == NULL)
    return 0;

  int r = hm->hm_cb(ha, hm);
  free(hm->hm_data);
  free(hm);

  if(r && ha->ha_run == 2) {
    if(hap_check_config_hash(ha)) {
      hap_mdns_update(ha);
      hap_accessory_lts_save(ha, false);
    }
  }

  return 1;
}


static void
hap_remove_stale_service_state(hap_accessory_t *ha)
{
  // Remove service state that it's not in use.
  hap_service_state_t *hss, *n;
  for(hss = LIST_FIRST(&ha->ha_service_states); hss != NULL; hss = n) {
    n = LIST_NEXT(hss, hss_link);
    if(hss->hss_service == NULL) {
      LIST_REMOVE(hss, hss_link);
      free(hss);
    }
  }
}




static void *
hap_thread(void *aux)
{
  hap_accessory_t *ha = aux;

  ha->ha_ap = avahi_simple_poll_get(ha->ha_asp);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) {
    hap_log(ha, NULL, LOG_ERR, "Failed to create socket: %s", strerror(errno));
    return NULL;
  }
  struct sockaddr_in sin = {.sin_family = AF_INET};
  if(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    hap_log(ha, NULL, LOG_ERR, "Failed to bind port for HTTP server: %s",
            strerror(errno));
    close(fd);
    return NULL;
  }
  socklen_t slen = sizeof(sin);
  if(getsockname(fd, (struct sockaddr *)&sin, &slen)) {
    hap_log(ha, NULL, LOG_ERR, "getsockname(): %s",
            strerror(errno));
    close(fd);
    return NULL;
  }

  ha->ha_http_listen_port = ntohs(sin.sin_port);
  hap_log(ha, NULL, LOG_INFO, "Listening on port %d", ha->ha_http_listen_port);

  listen(fd, 1);

  while(dispatch_message(ha)) {}

  if(hap_check_config_hash(ha))
    hap_accessory_lts_save(ha, false);

  AvahiClient *mdns_client =
    avahi_client_new(ha->ha_ap, AVAHI_CLIENT_NO_FAIL, client_callback, ha,
                     NULL);

  AvahiWatch *http_server_watch =
    ha->ha_ap->watch_new(ha->ha_ap, fd, AVAHI_WATCH_IN,
                         http_new_connection, ha);

  if(ha->ha_run == 1)
    ha->ha_run = 2;

  while(ha->ha_run && (avahi_simple_poll_iterate(ha->ha_asp, -1)) != -1) {
    dispatch_message(ha);
  }

  while(dispatch_message(ha)) {}

  hap_log(ha, NULL, LOG_INFO, "Shutting down");

  avahi_client_free(mdns_client);
  ha->ha_ap->watch_free(http_server_watch);

  close(fd);

  hap_connection_t *hc;
  while((hc = LIST_FIRST(&ha->ha_connections)) != NULL)
    http_delete_connection(hc);

  hap_remove_stale_service_state(ha);

  hap_accessory_lts_save(ha, false);

  avahi_simple_poll_free(ha->ha_asp);
  return NULL;
}

void
hap_msg_enqueue(hap_accessory_t *ha, hap_msg_t *hm,
                int (*cb)(hap_accessory_t *ha, hap_msg_t *hm))
{
  hm->hm_cb = cb;
  pthread_mutex_lock(&ha->ha_msg_mutex);
  TAILQ_INSERT_TAIL(&ha->ha_msg_queue, hm, hm_link);
  pthread_mutex_unlock(&ha->ha_msg_mutex);
  avahi_simple_poll_wakeup(ha->ha_asp);
}

void
hap_network_init(hap_accessory_t *ha)
{
  ha->ha_asp = avahi_simple_poll_new();
}


void
hap_network_start(hap_accessory_t *ha)
{
  ha->ha_run = 1;
  pthread_create(&ha->ha_tid, NULL, hap_thread, ha);
}


static int
hap_stop_on_thread(hap_accessory_t *ha, hap_msg_t *hm)
{
  ha->ha_run = 0;
  return 0;
}

void
hap_network_stop(hap_accessory_t *ha)
{
  hap_msg_t *hm = calloc(1, sizeof(hap_msg_t));
  hap_msg_enqueue(ha, hm, hap_stop_on_thread);
  pthread_join(ha->ha_tid, NULL);
}


