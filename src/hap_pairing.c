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
#include <assert.h>
#include <syslog.h>
#include <sys/param.h>

#include <openssl/srp.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include "hap_i.h"

// Table 5.5
#define kTLVError_Authentication 0x02
#define kTLVError_Unavailable    0x06

// Table 5.6
#define kTLVType_Method 0x00
#define kTLVType_Identifier 0x01
#define kTLVType_Salt 0x02
#define kTLVType_PublicKey 0x03
#define kTLVType_Proof 0x04
#define kTLVType_EncryptedData 0x05
#define kTLVType_State 0x06
#define kTLVType_Error 0x07
#define kTLVType_RetryDelay 0x08
#define kTLVType_Certificate 0x09
#define kTLVType_Signature 0x0A
#define kTLVType_Permissions 0x0B
#define kTLVType_FragmentData 0x0C
#define kTLVType_FragmentLast 0x0D
#define kTLVType_Flags 0x13
#define kTLVType_Separator 0xFF





typedef struct pair_setup_ctx {

  const BIGNUM *N;
  const BIGNUM *g;

  uint8_t salt[16];

  BIGNUM *b; // our private key
  BIGNUM *B; // our public key

  BIGNUM *A; // Client's public key
  BIGNUM *v; // Verifier

  uint8_t K[64];  // Session Key

  uint8_t client_proof[64];
  uint8_t server_proof[64];

} pair_setup_ctx_t;



static void
digest_bn(EVP_MD_CTX *ctx, const BIGNUM *bn)
{
  const int len = BN_num_bytes(bn);
  uint8_t *data = alloca(len);
  BN_bn2bin(bn, data);
  EVP_DigestUpdate(ctx, data, len);
}

static BIGNUM *
srp_padded_digest(const BIGNUM *x, const BIGNUM *y, const BIGNUM *N)
{
  const int nlen = BN_num_bytes(N);
  uint8_t digest[64];
  uint8_t buf[nlen * 2];

  BN_bn2binpad(x, buf,        nlen);
  BN_bn2binpad(y, buf + nlen, nlen);
  EVP_Digest(buf, nlen * 2, digest, NULL, EVP_sha512(), NULL);
  return BN_bin2bn(digest, sizeof(digest), NULL);
}


static BIGNUM *
srp_calc_b(const BIGNUM *b, const BIGNUM *N, const BIGNUM *g, const BIGNUM *v)
{
  BIGNUM *k = srp_padded_digest(N, g, N);
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *B = BN_new();
  BIGNUM *t0 = BN_new();
  BIGNUM *t1 = BN_new();

  BN_mod_exp(t0, g, b, N, ctx);
  BN_mod_mul(t1, v, k, N, ctx);
  BN_mod_add(B, t0, t1, N, ctx);

  BN_CTX_free(ctx);
  BN_clear_free(t0);
  BN_clear_free(t1);
  BN_clear_free(k);
  return B;
}


static pair_setup_ctx_t *
pair_setup_ctx_init(const uint8_t salt[static 16], const uint8_t b[static 32],
                    const char *username, const char *password)
{
  uint8_t rb[32];
  if(b == NULL) {
    if(hap_get_random_bytes(rb, sizeof(rb))) {
      return NULL;
    }
    b = rb;
  }

  pair_setup_ctx_t *psc = calloc(1, sizeof(pair_setup_ctx_t));

  if(salt != NULL) {
    memcpy(psc->salt, salt, sizeof(psc->salt));
  } else {
    if(hap_get_random_bytes(psc->salt, sizeof(psc->salt))) {
      free(psc);
      return NULL;
    }
  }

  SRP_gN *gN = SRP_get_default_gN("3072");
  psc->N = gN->N;
  psc->g = gN->g;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned char digest[64];

  EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
  EVP_DigestUpdate(ctx, username, strlen(username));
  EVP_DigestUpdate(ctx, ":", 1);
  EVP_DigestUpdate(ctx, password, strlen(password));
  EVP_DigestFinal_ex(ctx, digest, NULL);

  EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
  EVP_DigestUpdate(ctx, psc->salt, sizeof(psc->salt));
  EVP_DigestUpdate(ctx, digest, sizeof(digest));
  EVP_DigestFinal_ex(ctx, digest, NULL);
  EVP_MD_CTX_free(ctx);

  BIGNUM *x = BN_bin2bn(digest, sizeof(digest), NULL);
  BN_CTX *bn_ctx = BN_CTX_new();

  psc->v = BN_new();
  BN_mod_exp(psc->v, psc->g, x, psc->N, bn_ctx);
  BN_CTX_free(bn_ctx);
  BN_clear_free(x);

  psc->b = BN_bin2bn(b, 32, NULL);
  psc->B = srp_calc_b(psc->b, psc->N, psc->g, psc->v);
  return psc;
}


static void
pair_setup_ctx_calc_u_S_K(pair_setup_ctx_t *psc)
{
  BIGNUM *u = srp_padded_digest(psc->A, psc->B, psc->N);
  BIGNUM *S = SRP_Calc_server_key(psc->A, psc->v, u, psc->b, psc->N);

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
  digest_bn(ctx, S);
  EVP_DigestFinal_ex(ctx, psc->K, NULL);
  EVP_MD_CTX_free(ctx);
  BN_clear_free(u);
  BN_clear_free(S);
}

static void
pair_setup_ctx_calc_proof(pair_setup_ctx_t *psc, const char *username)
{
  uint8_t d1[64];
  uint8_t d2[64];

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
  digest_bn(ctx, psc->N);
  EVP_DigestFinal_ex(ctx, d1, NULL);

  EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
  digest_bn(ctx, psc->g);
  EVP_DigestFinal_ex(ctx, d2, NULL);

  for(int i = 0; i < sizeof(d1); i++)
    d1[i] ^= d2[i];

  EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
  EVP_DigestUpdate(ctx, username, strlen(username));
  EVP_DigestFinal_ex(ctx, d2, NULL);

  EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
  EVP_DigestUpdate(ctx, d1, sizeof(d1));
  EVP_DigestUpdate(ctx, d2, sizeof(d2));
  EVP_DigestUpdate(ctx, psc->salt, sizeof(psc->salt));
  digest_bn(ctx, psc->A);
  digest_bn(ctx, psc->B);
  EVP_DigestUpdate(ctx, psc->K, sizeof(psc->K));
  EVP_DigestFinal_ex(ctx, psc->client_proof, NULL);

  EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
  digest_bn(ctx, psc->A);
  EVP_DigestUpdate(ctx, psc->client_proof, sizeof(psc->client_proof));
  EVP_DigestUpdate(ctx, psc->K, sizeof(psc->K));
  EVP_DigestFinal_ex(ctx, psc->server_proof, NULL);

  EVP_MD_CTX_free(ctx);

}



void
hap_pair_setup_ctx_free(struct pair_setup_ctx *psc)
{
  BN_clear_free(psc->b);
  BN_clear_free(psc->B);
  BN_clear_free(psc->A);
  BN_clear_free(psc->v);
  free(psc);
}


static void
derive_key(const uint8_t *K, size_t K_len, uint8_t *output, size_t output_len,
           const char *salt, const char *info)
{
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

  EVP_PKEY_derive_init(pctx);
  EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512());
  EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, strlen(salt));
  EVP_PKEY_CTX_set1_hkdf_key(pctx, K, K_len);
  EVP_PKEY_CTX_add1_hkdf_info(pctx, info, strlen(info));

  EVP_PKEY_derive(pctx, output, &output_len);
  EVP_PKEY_CTX_free(pctx);
}



static void
output_tlv(buf_t *b, uint8_t type, size_t length, const void *value)
{
  while(1) {
    size_t c = MIN(length, 255);
    buf_append_u8(b, type);
    buf_append_u8(b, c);
    buf_append(b, value, c);
    length -= c;
    if(!length)
      return;
    value += c;
  }
}



static void
output_tlv_bn(buf_t *b, uint8_t type, BIGNUM *bn)
{
  const int len = BN_num_bytes(bn);
  uint8_t *data = alloca(len);
  BN_bn2bin(bn, data);
  output_tlv(b, type, len, data);
}


struct tlv {
  uint8_t *value;
  int len;
};


static int
parse_tlv(uint8_t *data, int len, struct tlv *tlvs, size_t max_tlv)
{
  memset(tlvs, 0, sizeof(struct tlv) * max_tlv);
  while(len > 2) {
    const uint8_t tlv_type = data[0];
    const uint8_t tlv_length = data[1];
    len -= 2;
    data += 2;
    if(len < tlv_length)
      return -1;

    if(tlv_type < max_tlv) {
      if(tlvs[tlv_type].value) {
        memmove(tlvs[tlv_type].value + tlvs[tlv_type].len,
                data, tlv_length);
      } else {
        tlvs[tlv_type].value = data;
      }
      tlvs[tlv_type].len += tlv_length;
    }
    data += tlv_length;
    len -= tlv_length;
  }

#if 0
  for(int i = 0; i < max_tlv; i++) {
    if(tlvs[i].value) {
      char tmp[64];
      snprintf(tmp, sizeof(tmp), "TLV-0x%02x", i);
      hexdump(tmp, tlvs[i].value, tlvs[i].len);
    }
  }
#endif
  return 0;
}


static int
decrypt_data(uint8_t *data, int len, const uint8_t *key, const char *nonce)
{
  if(len < 17)
    return -1;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, strlen(nonce), NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                      data + len - 16);

  EVP_DecryptInit_ex(ctx, NULL, NULL, key, (const void *)nonce);

  uint8_t plaintext[len - 16];
  int outlen = 0;
  if(!EVP_DecryptUpdate(ctx, plaintext, &outlen, data, len - 16)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if(!EVP_DecryptFinal_ex(ctx, plaintext, &outlen)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  memcpy(data, plaintext, len - 16);
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}


static int
decrypt_tlv(struct tlv *tlv, const uint8_t *key, const char *nonce)
{
  if(decrypt_data(tlv->value, tlv->len, key, nonce))
    return -1;

  tlv->len -= 16;
  return 0;
}


static size_t
encrypt_buf(uint8_t *output, size_t output_len,
            const buf_t *src, const uint8_t *key,
            const char *nonce)
{
  const size_t total_len = src->size + 16;
  if(total_len > output_len)
    return 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, strlen(nonce), NULL);

  EVP_EncryptInit_ex(ctx, NULL, NULL, key, (const void *)nonce);

  int outlen;
  if(!EVP_EncryptUpdate(ctx, output, &outlen, src->data, src->size)) {
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }

  output += outlen;
  if(!EVP_EncryptFinal_ex(ctx, output, &outlen)) {
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, output);
  EVP_CIPHER_CTX_free(ctx);
  return total_len;
}



static EVP_PKEY *
make_pkey(int id)
{
  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);
  EVP_PKEY_keygen_init(pctx);
  EVP_PKEY_keygen(pctx, &pkey);
  EVP_PKEY_CTX_free(pctx);
  return pkey;
}

static void
long_term_sign(const hap_accessory_t *ha, uint8_t signature[static 64],
               const void *tbs, size_t tbs_size)
{
  size_t AccessorySignature_size = 64;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestSignInit(ctx, NULL, NULL, NULL, ha->ha_long_term_key);
  EVP_DigestSign(ctx, signature, &AccessorySignature_size, tbs, tbs_size);
  EVP_MD_CTX_free(ctx);
}




static size_t
concat3(uint8_t *output, size_t output_len,
        const void *a, size_t a_len,
        const void *b, size_t b_len,
        const void *c, size_t c_len)
{
  const size_t total_len = a_len + b_len + c_len;
  if(total_len > output_len)
    return 0;

  memcpy(output, a,              a_len);
  memcpy(output + a_len,         b, b_len);
  memcpy(output + a_len + b_len, c, c_len);
  return total_len;
}


static int
pair_setup_error(hap_connection_t *hc, uint8_t state, uint8_t code)
{
  scoped_buf_t b = {};
  output_tlv(&b, kTLVType_State, 1, &state);
  output_tlv(&b, kTLVType_Error, 1, &code);
  return hap_http_send_reply(hc, 200, b.data, b.size,
                             "application/pairing+tlv8");
}

static int
pair_setup_m1(hap_connection_t *hc, struct tlv *tlvs)
{
  hap_accessory_t *ha = hc->hc_ha;
  if(LIST_FIRST(&ha->ha_peers) != NULL) {
    return pair_setup_error(hc, 4, kTLVError_Unavailable);
  }

  pair_setup_ctx_t *psc = hc->hc_psc;

  scoped_buf_t reply = {};
  output_tlv(&reply, kTLVType_State, 1, (const uint8_t []){2});
  output_tlv(&reply, kTLVType_Salt, sizeof(psc->salt), psc->salt);
  output_tlv_bn(&reply, kTLVType_PublicKey, psc->B);
  return hap_http_send_reply(hc, 200, reply.data, reply.size,
                             "application/pairing+tlv8");
}


static int
pair_setup_m3(hap_connection_t *hc, struct tlv *tlvs)
{
  pair_setup_ctx_t *psc = hc->hc_psc;

  if(tlvs[kTLVType_PublicKey].value == NULL ||
     tlvs[kTLVType_Proof].value == NULL)
    return -1;

  psc->A = BN_bin2bn(tlvs[kTLVType_PublicKey].value,
                     tlvs[kTLVType_PublicKey].len, NULL);

  pair_setup_ctx_calc_u_S_K(psc);
  pair_setup_ctx_calc_proof(psc, "Pair-Setup");

  if(tlvs[kTLVType_Proof].len != sizeof(psc->client_proof) ||
     memcmp(tlvs[kTLVType_Proof].value, psc->client_proof,
            sizeof(psc->client_proof))) {
    hap_log(hc->hc_ha, hc, LOG_WARNING,
            "pair-setup: Incorrect proof received (incorrect setup code?)");
    return pair_setup_error(hc, 4, kTLVError_Authentication);
  }

  scoped_buf_t reply = {};
  output_tlv(&reply, kTLVType_State, 1, (const uint8_t []){4});
  output_tlv(&reply, kTLVType_Proof, sizeof(psc->server_proof),
             psc->server_proof);
  return hap_http_send_reply(hc, 200, reply.data, reply.size,
                             "application/pairing+tlv8");
}



static int
pair_setup_m5(hap_connection_t *hc, struct tlv *tlvs)
{
  hap_accessory_t *ha = hc->hc_ha;
  pair_setup_ctx_t *psc = hc->hc_psc;
  uint8_t tmp[4096];

  if(tlvs[kTLVType_EncryptedData].value == NULL)
    return -1;

  uint8_t key[32] = {};
  derive_key(psc->K, sizeof(psc->K), key, sizeof(key),
             "Pair-Setup-Encrypt-Salt",
             "Pair-Setup-Encrypt-Info");

  if(decrypt_tlv(&tlvs[kTLVType_EncryptedData], key, "PS-Msg05")) {
    return pair_setup_error(hc, 6, kTLVError_Authentication);
  }

  struct tlv subtlvs[kTLVType_Flags + 1];
  if(parse_tlv(tlvs[kTLVType_EncryptedData].value,
               tlvs[kTLVType_EncryptedData].len,
               subtlvs, ARRAYSIZE(subtlvs))) {
    hap_log(hc->hc_ha, hc, LOG_WARNING,
            "pair-setup: Corrupted encrypted TLVs");
    return -1;
  }

  if(subtlvs[kTLVType_Identifier].value == NULL ||
     subtlvs[kTLVType_PublicKey].value == NULL ||
     subtlvs[kTLVType_Signature].value == NULL) {
    return -1;
  }

  derive_key(psc->K, sizeof(psc->K), key, sizeof(key),
             "Pair-Setup-Controller-Sign-Salt",
             "Pair-Setup-Controller-Sign-Info");

  const size_t iOSDeviceInfo_len =
    concat3(tmp, sizeof(tmp),
            key, sizeof(key),
            subtlvs[kTLVType_Identifier].value,
            subtlvs[kTLVType_Identifier].len,
            subtlvs[kTLVType_PublicKey].value,
            subtlvs[kTLVType_PublicKey].len);


  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_PKEY *pkey =
    EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                subtlvs[kTLVType_PublicKey].value,
                                subtlvs[kTLVType_PublicKey].len);

  EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
  int rv = EVP_DigestVerify(ctx,
                            subtlvs[kTLVType_Signature].value,
                            subtlvs[kTLVType_Signature].len,
                            tmp, iOSDeviceInfo_len);
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  pkey = NULL;
  if(rv != 1)
    return pair_setup_error(hc, 6, kTLVError_Authentication);

  hap_peer_t *hp = calloc(1, sizeof(hap_peer_t));
  hp->hp_id = strndup((const void *)subtlvs[kTLVType_Identifier].value,
                      subtlvs[kTLVType_Identifier].len);

  memcpy(hp->hp_public_key, subtlvs[kTLVType_PublicKey].value,
         sizeof(hp->hp_public_key));
  LIST_INSERT_HEAD(&ha->ha_peers, hp, hp_link);
  hp->hp_flags = HAP_PEER_ADMIN;
  hap_accessory_lts_save(ha);

  hap_log(hc->hc_ha, hc, LOG_INFO, "Added first peer %s, admin", hp->hp_id);

  // Generate reply

  uint8_t *AccessoryLTPK;
  size_t AccessoryLTPK_size;
  EVP_PKEY_get_raw_public_key(hc->hc_ha->ha_long_term_key, NULL,
                              &AccessoryLTPK_size);
  AccessoryLTPK = alloca(AccessoryLTPK_size);
  memset(AccessoryLTPK, 0, AccessoryLTPK_size);
  EVP_PKEY_get_raw_public_key(hc->hc_ha->ha_long_term_key, AccessoryLTPK,
                              &AccessoryLTPK_size);

  derive_key(psc->K, sizeof(psc->K), key, sizeof(key),
             "Pair-Setup-Accessory-Sign-Salt",
             "Pair-Setup-Accessory-Sign-Info");

  const size_t AccessoryInfo_len =
    concat3(tmp, sizeof(tmp),
            key, sizeof(key),
            hc->hc_ha->ha_id, strlen(hc->hc_ha->ha_id),
            AccessoryLTPK, AccessoryLTPK_size);

  uint8_t AccessorySignature[64];
  long_term_sign(hc->hc_ha, AccessorySignature, tmp, AccessoryInfo_len);

  scoped_buf_t subtlv = {};

  output_tlv(&subtlv, kTLVType_Identifier, strlen(hc->hc_ha->ha_id),
             hc->hc_ha->ha_id);
  output_tlv(&subtlv, kTLVType_PublicKey, AccessoryLTPK_size,
             AccessoryLTPK);
  output_tlv(&subtlv, kTLVType_Signature, sizeof(AccessorySignature),
             AccessorySignature);

  derive_key(psc->K, sizeof(psc->K), key, sizeof(key),
             "Pair-Setup-Encrypt-Salt",
             "Pair-Setup-Encrypt-Info");

  size_t EncryptedData_len =
    encrypt_buf(tmp, sizeof(tmp), &subtlv, key, "PS-Msg06");

  scoped_buf_t reply = {};
  output_tlv(&reply, kTLVType_State, 1, (const uint8_t []){6});
  output_tlv(&reply, kTLVType_EncryptedData, EncryptedData_len, tmp);

  if(hap_http_send_reply(hc, 200, reply.data, reply.size,
                         "application/pairing+tlv8"))
    return -1;

  hap_mdns_update(ha);
  return 0;
}


int
hap_pair_setup(hap_connection_t *hc, enum http_method method,
               uint8_t *request_body, size_t request_body_len,
               const hap_query_args_t *qa)
{
  hap_accessory_t *ha = hc->hc_ha;
  scoped_buf_t reply = {};

  if(hc->hc_psc == NULL) {
    hc->hc_psc = pair_setup_ctx_init(NULL, NULL, "Pair-Setup",
                                     ha->ha_password);
    if(hc->hc_psc == NULL) {
      hap_log(ha, hc, LOG_WARNING, "pair-setup: Unable to initialize context");
      return -1;
    }
  }
  struct tlv tlvs[kTLVType_Flags + 1];

  if(parse_tlv(request_body, request_body_len, tlvs, ARRAYSIZE(tlvs))) {
    hap_log(ha, hc, LOG_WARNING, "pair-setup: Corrupted TLVs");
    return -1;
  }

  if(!tlvs[kTLVType_State].value || tlvs[kTLVType_State].len != 1) {
    hap_log(ha, hc, LOG_WARNING, "pair-setup: No state");
    return -1;
  }
  const uint8_t state = tlvs[kTLVType_State].value[0];
  hap_log(hc->hc_ha, hc, LOG_DEBUG, "pair-setup: In state %d", state);

  switch(state) {

  case 1:
    return pair_setup_m1(hc, tlvs);
  case 3:
    return pair_setup_m3(hc, tlvs);
  case 5:
    return pair_setup_m5(hc, tlvs);
  default:
    return -1;
  }
}


// 5.7.2  M2: Accessory - > iOS Device – ‘Verify Start Responseʼ
static int
pair_verify_m2(hap_connection_t *hc, struct tlv *tlvs)
{
  if(tlvs[kTLVType_PublicKey].value == NULL)
    return -1;

  hap_accessory_t *ha = hc->hc_ha;
  uint8_t SharedSecret[32];
  uint8_t tmp[4096];

  EVP_PKEY *pkey = make_pkey(EVP_PKEY_X25519);

  EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                               tlvs[kTLVType_PublicKey].value,
                                               tlvs[kTLVType_PublicKey].len);

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
  EVP_PKEY_derive_init(pctx);
  EVP_PKEY_derive_set_peer(pctx, peer);
  size_t size = sizeof(SharedSecret);
  EVP_PKEY_derive(pctx, SharedSecret, &size);

  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(peer);

  uint8_t *AccessoryPK;
  size_t AccessoryPK_size;
  EVP_PKEY_get_raw_public_key(pkey, NULL, &AccessoryPK_size);
  AccessoryPK = alloca(AccessoryPK_size);
  EVP_PKEY_get_raw_public_key(pkey, AccessoryPK, &AccessoryPK_size);
  EVP_PKEY_free(pkey);

  const size_t AccessoryInfo_len =
    concat3(tmp, sizeof(tmp),
            AccessoryPK, AccessoryPK_size,
            ha->ha_id, strlen(ha->ha_id),
            tlvs[kTLVType_PublicKey].value, tlvs[kTLVType_PublicKey].len);


  uint8_t AccessorySignature[64];
  long_term_sign(ha, AccessorySignature, tmp, AccessoryInfo_len);

  scoped_buf_t subtlv = {};
  output_tlv(&subtlv, kTLVType_Identifier, strlen(ha->ha_id),
             ha->ha_id);
  output_tlv(&subtlv, kTLVType_Signature, sizeof(AccessorySignature),
             AccessorySignature);

  derive_key(SharedSecret, sizeof(SharedSecret),
             hc->hc_SessionKey, sizeof(hc->hc_SessionKey),
             "Pair-Verify-Encrypt-Salt",
             "Pair-Verify-Encrypt-Info");

  derive_key(SharedSecret, sizeof(SharedSecret),
             hc->hc_SendKey, sizeof(hc->hc_SendKey),
             "Control-Salt",
             "Control-Read-Encryption-Key");

  derive_key(SharedSecret, sizeof(SharedSecret),
             hc->hc_RecvKey, sizeof(hc->hc_RecvKey),
             "Control-Salt",
             "Control-Write-Encryption-Key");

  size_t EncryptedData_len =
    encrypt_buf(tmp, sizeof(tmp), &subtlv, hc->hc_SessionKey, "PV-Msg02");

  scoped_buf_t reply = {};
  output_tlv(&reply, kTLVType_State, 1, (const uint8_t []){2});
  output_tlv(&reply, kTLVType_PublicKey, AccessoryPK_size, AccessoryPK);
  output_tlv(&reply, kTLVType_EncryptedData, EncryptedData_len, tmp);
  return hap_http_send_reply(hc, 200, reply.data, reply.size,
                             "application/pairing+tlv8");
}

// 5.7.4 M4: Accessory - > iOS Device – ‘Verify Finish Responseʼ
static int
pair_verify_m4(hap_connection_t *hc, struct tlv *tlvs)
{
  if(tlvs[kTLVType_EncryptedData].value == NULL)
    return -1;

  hap_accessory_t *ha = hc->hc_ha;
  if(decrypt_tlv(&tlvs[kTLVType_EncryptedData], hc->hc_SessionKey,
                 "PV-Msg03")) {
    return pair_setup_error(hc, 4, kTLVError_Authentication);
  }

  struct tlv subtlvs[kTLVType_Flags + 1];

  if(parse_tlv(tlvs[kTLVType_EncryptedData].value,
               tlvs[kTLVType_EncryptedData].len,
               subtlvs, ARRAYSIZE(subtlvs))) {
    hap_log(hc->hc_ha, hc, LOG_WARNING,
            "pair-setup: Corrupted encrypted TLVs");
    return -1;
  }

  if(subtlvs[kTLVType_Identifier].value == NULL)
    return -1;

  scoped_char *peername =
    strndup((const char *)subtlvs[kTLVType_Identifier].value,
            subtlvs[kTLVType_Identifier].len);

  hap_peer_t *hp;
  LIST_FOREACH(hp, &ha->ha_peers, hp_link) {
    if(!strcmp(hp->hp_id, peername))
      break;
  }

  if(hp == NULL) {
    return pair_setup_error(hc, 4, kTLVError_Authentication);
  }

  scoped_buf_t reply = {};
  output_tlv(&reply, kTLVType_State, 1, (const uint8_t []){4});
  if(hap_http_send_reply(hc, 200, reply.data, reply.size,
                         "application/pairing+tlv8"))
    return -1;
  // We're fully verified, turn on encryption
  hc->hc_cipher_context = EVP_CIPHER_CTX_new();
  hc->hc_peer_flags = hp->hp_flags;

  hap_log(hc->hc_ha, hc, LOG_DEBUG, "Peer verified, encryption enabled");

  char *log_prefix = fmt("%s [%s]", hc->hc_log_prefix, peername);
  free(hc->hc_log_prefix);
  hc->hc_log_prefix = log_prefix;
  return 0;
}


int
hap_pair_verify(hap_connection_t *hc, enum http_method method,
                uint8_t *request_body, size_t request_body_len,
                const hap_query_args_t *qa)
{
  hap_accessory_t *ha = hc->hc_ha;
  struct tlv tlvs[kTLVType_Flags + 1];

  if(parse_tlv(request_body, request_body_len, tlvs, ARRAYSIZE(tlvs))) {
    hap_log(ha, hc, LOG_WARNING, "pair-verify: Corrupted TLVs");
    return -1;
  }

  if(!tlvs[kTLVType_State].value || tlvs[kTLVType_State].len != 1) {
    hap_log(ha, hc, LOG_WARNING, "pair-verify: No state");
    return -1;
  }
  const uint8_t state = tlvs[kTLVType_State].value[0];
  hap_log(ha, hc, LOG_DEBUG, "pair-verify: In state %d", state);

  switch(state) {
  case 1:
    return pair_verify_m2(hc, tlvs);
  case 3:
    return pair_verify_m4(hc, tlvs);
  default:
    return -1;
  }
}


static int
pairing_add(hap_connection_t *hc, struct tlv *tlvs)
{
  if(tlvs[kTLVType_Identifier].value == NULL)
    return -1;

  hap_accessory_t *ha = hc->hc_ha;

  if(!(hc->hc_peer_flags & HAP_PEER_ADMIN))
    return pair_setup_error(hc, 2, kTLVError_Authentication);

  scoped_char *peername =
    strndup((const char *)tlvs[kTLVType_Identifier].value,
            tlvs[kTLVType_Identifier].len);

  if(tlvs[kTLVType_PublicKey].len != 32)
    return -1;

  hap_peer_t *hp;
  LIST_FOREACH(hp, &ha->ha_peers, hp_link) {
    if(!strcmp(hp->hp_id, peername))
      break;
  }

  const char *verb;

  if(hp == NULL) {
    hp = calloc(1, sizeof(hap_peer_t));
    hp->hp_id = strdup(peername);
    LIST_INSERT_HEAD(&ha->ha_peers, hp, hp_link);
    memcpy(hp->hp_public_key, tlvs[kTLVType_PublicKey].value,
           sizeof(hp->hp_public_key));
    verb = "Added";
  } else {

    if(memcmp(hp->hp_public_key, tlvs[kTLVType_PublicKey].value,
              sizeof(hp->hp_public_key))) {

      return pair_setup_error(hc, 2, kTLVError_Authentication);
    }
    verb = "Updated";
  }

  hp->hp_flags = tlvs[kTLVType_Permissions].len == 1 ?
    tlvs[kTLVType_Permissions].value[0] : 0;

  hap_log(hc->hc_ha, hc, LOG_INFO,
          "%s peer %s%s", verb, hp->hp_id, hp->hp_flags &
          HAP_PEER_ADMIN ? ", admin" : "");

  hap_accessory_lts_save(ha);

  scoped_buf_t reply = {};
  output_tlv(&reply, kTLVType_State, 1, (const uint8_t []){2});
  return hap_http_send_reply(hc, 200, reply.data, reply.size,
                             "application/pairing+tlv8");
}

static int
pairing_remove(hap_connection_t *hc, struct tlv *tlvs)
{
  if(tlvs[kTLVType_Identifier].value == NULL)
    return -1;

  hap_accessory_t *ha = hc->hc_ha;

  if(!(hc->hc_peer_flags & HAP_PEER_ADMIN))
    return pair_setup_error(hc, 2, kTLVError_Authentication);

  scoped_char *peername =
    strndup((const char *)tlvs[kTLVType_Identifier].value,
            tlvs[kTLVType_Identifier].len);

  hap_peer_t *hp;
  LIST_FOREACH(hp, &ha->ha_peers, hp_link) {
    if(!strcmp(hp->hp_id, peername))
      break;
  }

  if(hp != NULL) {
    hap_log(hc->hc_ha, hc, LOG_INFO,
            "Removed peer %s%s", hp->hp_id, hp->hp_flags &
            HAP_PEER_ADMIN ? ", admin" : "");
    free(hp->hp_id);
    LIST_REMOVE(hp, hp_link);
  }

  hap_accessory_lts_save(ha);

  scoped_buf_t reply = {};
  output_tlv(&reply, kTLVType_State, 1, (const uint8_t []){2});
  return hap_http_send_reply(hc, 200, reply.data, reply.size,
                             "application/pairing+tlv8");
}


int
hap_pairings(hap_connection_t *hc, enum http_method http_method,
             uint8_t *request_body, size_t request_body_len,
             const hap_query_args_t *qa)
{
  hap_accessory_t *ha = hc->hc_ha;
  struct tlv tlvs[kTLVType_Flags + 1];

  if(parse_tlv(request_body, request_body_len, tlvs, ARRAYSIZE(tlvs))) {
    hap_log(ha, hc, LOG_WARNING, "pairings: Corrupted TLVs");
    return -1;
  }

  if(!tlvs[kTLVType_Method].value || tlvs[kTLVType_Method].len != 1) {
    hap_log(ha, hc, LOG_WARNING, "pairings: No method set");
    return -1;
  }
  const uint8_t method = tlvs[kTLVType_Method].value[0];

  switch(method) {
  case 3: // Add Pairing
    return pairing_add(hc, tlvs);
  case 4: // Remove Pairing
    return pairing_remove(hc, tlvs);
  case 5: // List Parings
    break;
  }

  return -1;
}


#if 0

static void
print_bignum(const char *prefix, BIGNUM *v)
{
  fprintf(stdout, "%s=", prefix);
  BN_print_fp(stdout, v);
  printf("\n");
}

static void
srp_test(void)
{
  // 5.5.2 SRP Test Vectors

  const uint8_t test_salt[16] = {
    0xBE, 0xB2, 0x53, 0x79, 0xD1, 0xA8, 0x58, 0x1E,
    0xB5, 0xA7, 0x27, 0x67, 0x3A, 0x24, 0x41, 0xEE,
  };

  const uint8_t test_b[32] = {
    0xE4, 0x87, 0xCB, 0x59, 0xD3, 0x1A, 0xC5, 0x50,
    0x47, 0x1E, 0x81, 0xF0, 0x0F, 0x69, 0x28, 0xE0,
    0x1D, 0xDA, 0x08, 0xE9, 0x74, 0xA0, 0x04, 0xF4,
    0x9E, 0x61, 0xF5, 0xD1, 0x05, 0x28, 0x4D, 0x20
  };

  const uint8_t test_A[] = {
    0xFA, 0xB6, 0xF5, 0xD2, 0x61, 0x5D, 0x1E, 0x32,
    0x35, 0x12, 0xE7, 0x99, 0x1C, 0xC3, 0x74, 0x43,
    0xF4, 0x87, 0xDA, 0x60, 0x4C, 0xA8, 0xC9, 0x23,
    0x0F, 0xCB, 0x04, 0xE5, 0x41, 0xDC, 0xE6, 0x28,
    0x0B, 0x27, 0xCA, 0x46, 0x80, 0xB0, 0x37, 0x4F,
    0x17, 0x9D, 0xC3, 0xBD, 0xC7, 0x55, 0x3F, 0xE6,
    0x24, 0x59, 0x79, 0x8C, 0x70, 0x1A, 0xD8, 0x64,
    0xA9, 0x13, 0x90, 0xA2, 0x8C, 0x93, 0xB6, 0x44,
    0xAD, 0xBF, 0x9C, 0x00, 0x74, 0x5B, 0x94, 0x2B,
    0x79, 0xF9, 0x01, 0x2A, 0x21, 0xB9, 0xB7, 0x87,
    0x82, 0x31, 0x9D, 0x83, 0xA1, 0xF8, 0x36, 0x28,
    0x66, 0xFB, 0xD6, 0xF4, 0x6B, 0xFC, 0x0D, 0xDB,
    0x2E, 0x1A, 0xB6, 0xE4, 0xB4, 0x5A, 0x99, 0x06,
    0xB8, 0x2E, 0x37, 0xF0, 0x5D, 0x6F, 0x97, 0xF6,
    0xA3, 0xEB, 0x6E, 0x18, 0x20, 0x79, 0x75, 0x9C,
    0x4F, 0x68, 0x47, 0x83, 0x7B, 0x62, 0x32, 0x1A,
    0xC1, 0xB4, 0xFA, 0x68, 0x64, 0x1F, 0xCB, 0x4B,
    0xB9, 0x8D, 0xD6, 0x97, 0xA0, 0xC7, 0x36, 0x41,
    0x38, 0x5F, 0x4B, 0xAB, 0x25, 0xB7, 0x93, 0x58,
    0x4C, 0xC3, 0x9F, 0xC8, 0xD4, 0x8D, 0x4B, 0xD8,
    0x67, 0xA9, 0xA3, 0xC1, 0x0F, 0x8E, 0xA1, 0x21,
    0x70, 0x26, 0x8E, 0x34, 0xFE, 0x3B, 0xBE, 0x6F,
    0xF8, 0x99, 0x98, 0xD6, 0x0D, 0xA2, 0xF3, 0xE4,
    0x28, 0x3C, 0xBE, 0xC1, 0x39, 0x3D, 0x52, 0xAF,
    0x72, 0x4A, 0x57, 0x23, 0x0C, 0x60, 0x4E, 0x9F,
    0xBC, 0xE5, 0x83, 0xD7, 0x61, 0x3E, 0x6B, 0xFF,
    0xD6, 0x75, 0x96, 0xAD, 0x12, 0x1A, 0x87, 0x07,
    0xEE, 0xC4, 0x69, 0x44, 0x95, 0x70, 0x33, 0x68,
    0x6A, 0x15, 0x5F, 0x64, 0x4D, 0x5C, 0x58, 0x63,
    0xB4, 0x8F, 0x61, 0xBD, 0xBF, 0x19, 0xA5, 0x3E,
    0xAB, 0x6D, 0xAD, 0x0A, 0x18, 0x6B, 0x8C, 0x15,
    0x2E, 0x5F, 0x5D, 0x8C, 0xAD, 0x4B, 0x0E, 0xF8,
    0xAA, 0x4E, 0xA5, 0x00, 0x88, 0x34, 0xC3, 0xCD,
    0x34, 0x2E, 0x5E, 0x0F, 0x16, 0x7A, 0xD0, 0x45,
    0x92, 0xCD, 0x8B, 0xD2, 0x79, 0x63, 0x93, 0x98,
    0xEF, 0x9E, 0x11, 0x4D, 0xFA, 0xAA, 0xB9, 0x19,
    0xE1, 0x4E, 0x85, 0x09, 0x89, 0x22, 0x4D, 0xDD,
    0x98, 0x57, 0x6D, 0x79, 0x38, 0x5D, 0x22, 0x10,
    0x90, 0x2E, 0x9F, 0x9B, 0x1F, 0x2D, 0x86, 0xCF,
    0xA4, 0x7E, 0xE2, 0x44, 0x63, 0x54, 0x65, 0xF7,
    0x10, 0x58, 0x42, 0x1A, 0x01, 0x84, 0xBE, 0x51,
    0xDD, 0x10, 0xCC, 0x9D, 0x07, 0x9E, 0x6F, 0x16,
    0x04, 0xE7, 0xAA, 0x9B, 0x7C, 0xF7, 0x88, 0x3C,
    0x7D, 0x4C, 0xE1, 0x2B, 0x06, 0xEB, 0xE1, 0x60,
    0x81, 0xE2, 0x3F, 0x27, 0xA2, 0x31, 0xD1, 0x84,
    0x32, 0xD7, 0xD1, 0xBB, 0x55, 0xC2, 0x8A, 0xE2,
    0x1F, 0xFC, 0xF0, 0x05, 0xF5, 0x75, 0x28, 0xD1,
    0x5A, 0x88, 0x88, 0x1B, 0xB3, 0xBB, 0xB7, 0xFE,
  };

  pair_setup_ctx_t *psc =
    pair_setup_ctx_init(test_salt, test_b, "alice", "password123");

  print_bignum("b", psc->b);
  print_bignum("B", psc->B);

  psc->A = BN_bin2bn(test_A, sizeof(test_A), NULL);
  pair_setup_ctx_calc_u_S_K(psc);

  hexdump("K", psc->K, sizeof(psc->K));
}
#endif
