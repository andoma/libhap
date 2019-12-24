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

#include "hap.h"

#include <openssl/evp.h>

#include <pthread.h>
#include <sys/queue.h>

#include <netinet/in.h>

#include "http_parser.h"
#include "intvec.h"

#include "buf.h"

TAILQ_HEAD(hap_msg_queue, hap_msg);
LIST_HEAD(hap_service_state_list, hap_service_state);
TAILQ_HEAD(hap_service_queue, hap_service);
LIST_HEAD(hap_conection_list, hap_connection);
LIST_HEAD(hap_peer_list, hap_peer);

struct mbuf;


typedef struct hap_msg {
  TAILQ_ENTRY(hap_msg) hm_link;

  // If this returns 1 we recompute config hash
  int (*hm_cb)(hap_accessory_t *ha, struct hap_msg *hm);

  bool hm_local_echo;
  hap_value_t hm_value;

  hap_service_t *hm_hs;

  int hm_index;

  void *hm_data;

} hap_msg_t;


typedef struct hap_service_state {
  LIST_ENTRY(hap_service_state) hss_link;

  struct hap_service *hss_service;
  size_t hss_size;

  // Used to match saved state to hap_service instance
  uint8_t hss_config_digest[20];
  uint8_t hss_data[0];

} hap_service_state_t;




struct hap_service {

  TAILQ_ENTRY(hap_service) hs_link;
  int hs_aid;
  int hs_iid;

  struct hap_service_state *hs_state;

  char *hs_type;

  int hs_num_characteristics;

  hap_characteristic_t (*hs_characteristic_get)(void *opaque, int index);

  int (*hs_characteristic_set)(void *opaque, int index, hap_value_t value);

  void (*hs_init)(void *opaque);

  void (*hs_fini)(void *opaque);

  void *hs_opaque;

  struct hap_accessory *hs_ha;

  uint8_t hs_config_digest[20];

  hap_value_type_t hs_formats[0];
};


typedef struct hap_peer {
  LIST_ENTRY(hap_peer) hp_link;
  char *hp_id;
  uint8_t hp_public_key[32];
  uint8_t hp_flags;
} hap_peer_t;

#define HAP_PEER_ADMIN 0x1


struct hap_accessory {

  struct hap_peer_list ha_peers;

  struct hap_service_state_list ha_service_states;

  struct hap_service_queue ha_services;

  struct hap_conection_list ha_connections;

  char *ha_id; /* Announced over mDNS and also our AccessoryPairingID
                * Must be in mac-address form 'XX:XX:XX:XX:XX:XX'
                */
  char *ha_name;
  char *ha_manufacturer;
  char *ha_model;
  char *ha_version;
  char *ha_password;

  char *ha_storage_path;
  hap_accessory_category_t ha_category;

  EVP_PKEY *ha_long_term_key;

  int ha_http_listen_port;

  const struct AvahiPoll *ha_ap;
  struct AvahiSimplePoll *ha_asp;
  struct AvahiEntryGroup *ha_group;

  pthread_t ha_tid;

  hap_log_callback_t *ha_logcb;
  void *ha_opaque;

  pthread_mutex_t ha_msg_mutex;
  struct hap_msg_queue ha_msg_queue;

  int ha_run;

  uint8_t ha_config_hash[20];
  uint16_t ha_config_number;


};





typedef struct hap_connection {

  struct http_parser hc_parser;
  int hc_fd;
  struct AvahiWatch *hc_watch;

  buf_t hc_body;
  buf_t hc_path;
  buf_t hc_encrypted;

  struct pair_setup_ctx *hc_psc;

  struct sockaddr_in hc_remote_addr;

  hap_accessory_t *hc_ha;
  LIST_ENTRY(hap_connection) hc_link;

  uint8_t hc_SessionKey[32];
  uint8_t hc_SendKey[32];
  uint8_t hc_RecvKey[32];

  uint8_t hc_peer_flags;

  EVP_CIPHER_CTX *hc_cipher_context;
  uint32_t hc_encrypted_frames;
  uint32_t hc_decrypted_frames;

  intvec_t hc_watched_iids;

  char *hc_log_prefix;

} hap_connection_t;

typedef struct hap_query_args hap_query_args_t;

char *hap_http_get_qa(const hap_query_args_t *qa, const char *key);


// ==== hap.c ==============================================

void hap_accessory_lts_save(hap_accessory_t *ha);

void *hap_service_state_recall(hap_service_t *hs, size_t state_size);

int hap_characteristics(hap_connection_t *hc, enum http_method method,
                        uint8_t *request_body, size_t request_body_len,
                        const hap_query_args_t *qa);

int hap_accessories(hap_connection_t *hc, enum http_method method,
                    uint8_t *request_body, size_t request_body_len,
                    const hap_query_args_t *qa);

void hap_msg_enqueue(hap_accessory_t *ha, hap_msg_t *hm,
                     int (*cb)(hap_accessory_t *ha, hap_msg_t *hm));

void hap_log(const hap_accessory_t *ha, const hap_connection_t *hc, int level,
             const char *format, ...)
  __attribute__((format (printf, 4, 5)));

// ==== hap_network.c ==============================================

int hap_http_send_data(hap_connection_t *hc, const void *data, size_t len);

int hap_http_send_reply(hap_connection_t *hc, int status, const void *body,
                        size_t content_length, const char *content_type);

void hap_network_init(hap_accessory_t *ha);

void hap_network_start(hap_accessory_t *ha);

void hap_network_stop(hap_accessory_t *ha);

void hap_mdns_update(hap_accessory_t *ha);

// ==== hap_pairing.c ==============================================

int hap_pair_setup(hap_connection_t *hc, enum http_method method,
                   uint8_t *request_body, size_t request_body_len,
                   const hap_query_args_t *qa);

int hap_pair_verify(hap_connection_t *hc, enum http_method method,
                    uint8_t *request_body, size_t request_body_len,
                    const hap_query_args_t *qa);

int hap_pairings(hap_connection_t *hc, enum http_method method,
                 uint8_t *request_body, size_t request_body_len,
                 const hap_query_args_t *qa);

void hap_pair_setup_ctx_free(struct pair_setup_ctx *psc);

int hap_get_random_bytes(void *out, size_t len);

// Misc things

void hap_freecharp(char **ptr);

#define scoped_char char __attribute__((cleanup(hap_freecharp)))

char *fmtv(const char *fmt, va_list ap);

char *fmt(const char *fmt, ...)  __attribute__ ((format (printf, 1, 2)));

#define ARRAYSIZE(x) (sizeof(x) / sizeof(x[0]))


