#include "util.h"

#include <mongoose.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <sqlite3.h>
#include <sys/types.h>

#include "base64.h"
#include "db.h"

EVP_PKEY *load_pub_sig_key_from_spki(const uint8_t *buf, size_t len) {
  const uint8_t *p = buf;
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, len);
  if (!pkey) {
    fprintf(stderr, "[%s:%d] failed to parse SPKI\n", __func__, __LINE__);
    return NULL;
  }

  if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
    fprintf(stderr, "[%s:%d] not an RSA key\n", __func__, __LINE__);
    EVP_PKEY_free(pkey);
    return NULL;
  }

  int key_size = EVP_PKEY_get_size(pkey);
  int key_bits = key_size * 8;
  if (key_bits != 4096) {
    fprintf(stderr,
            "[%s:%d] RSA signing key must be 4096 bits (got: %d bits)\n",
            __func__, __LINE__, key_bits);
    EVP_PKEY_free(pkey);
    return NULL;
  }

  BIGNUM *e = NULL;
  if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1 || !e) {
    fprintf(stderr, "[%s:%d] failed to get RSA public exponent parameter\n",
            __func__, __LINE__);
    EVP_PKEY_free(pkey);
    BN_free(e);
    return NULL;
  }

  if (!BN_is_word(e, 65537)) {
    fprintf(stderr, "[%s:%d] unexpected RSA public exponent (expected 65537)\n",
            __func__, __LINE__);
    EVP_PKEY_free(pkey);
    BN_free(e);
    return NULL;
  }

  BN_free(e);

  return pkey;
}

EVP_PKEY *load_pub_enc_key_from_spki(const uint8_t *buf, size_t len) {
  const uint8_t *p = buf;
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, len);
  if (!pkey) {
    fprintf(stderr, "[%s:%d] failed to parse SPKI\n", __func__, __LINE__);
    return NULL;
  }

  if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
    fprintf(stderr, "[%s:%d] not an RSA key\n", __func__, __LINE__);
    EVP_PKEY_free(pkey);
    return NULL;
  }

  int key_size = EVP_PKEY_get_size(pkey);
  if (key_size < 256) {
    fprintf(stderr, "[%s:%d] RSA key too small (%d bits, need at least 2048)\n",
            __func__, __LINE__, key_size * 8);
    EVP_PKEY_free(pkey);
    return NULL;
  }

  return pkey;
}

int verify_signature(const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                     size_t sig_len, EVP_PKEY *pkey) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  int ret = 0;

  if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha512(), NULL, pkey) < 0) goto err;
  if (EVP_DigestVerifyUpdate(mdctx, msg, msg_len) < 0) goto err;
  if (EVP_DigestVerifyFinal(mdctx, sig, sig_len) != 1) goto err;

  ret = 1;
err:
  EVP_MD_CTX_free(mdctx);
  return ret;
}

int verify_request(struct mg_http_message *hm, EVP_PKEY *pkey) {
  int ret = -418;
  char *sig_buf = NULL;
  sqlite3_stmt *stmt = NULL;
  uint8_t *msg_buf = NULL;
  int supplied_pkey = !!pkey;

  struct mg_str *id = mg_http_get_header(hm, "X-Identity");
  struct mg_str *sig_b64 = mg_http_get_header(hm, "X-Signature");
  if ((!id && !pkey) || !sig_b64) {
    fprintf(stderr, "[%s:%d] missing required headers\n", __func__, __LINE__);
    ret = -400;
    goto err;
  }

  size_t sig_len = 0;
  sig_buf = b64_decode(sig_b64->buf, sig_b64->len, &sig_len);
  if (!sig_buf || sig_len == 0) {
    fprintf(stderr, "[%s:%d] decoding signature header failed\n", __func__,
            __LINE__);
    ret = -400;
    goto err;
  }

  if (pkey) goto check_signature;

  if (sqlite3_prepare_v3(db,
                         "select signing_key from identities where handle = ?;",
                         -1, 0, &stmt, NULL) < 0) {
    fprintf(stderr, "[%s:%d] prepare failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    ret = -500;
    goto err;
  }

  if (sqlite3_bind_text(stmt, 1, id->buf, id->len, SQLITE_STATIC) < 0) {
    fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    ret = -500;
    goto err;
  }

  int err = sqlite3_step(stmt);
  if (err == SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] unknown identity\n", __func__, __LINE__);
    ret = -401;
    goto err;
  }

  if (err != SQLITE_ROW) {
    fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    ret = -500;
    goto err;
  }

  const void *buf = sqlite3_column_blob(stmt, 0);
  int len = sqlite3_column_bytes(stmt, 0);

  if (!buf || len <= 0) {
    fprintf(stderr, "[%s:%d] invalid public key buffer\n", __func__, __LINE__);
    ret = -500;
    goto err;
  }

  if ((pkey = load_pub_sig_key_from_spki(buf, len)) == NULL) {
    ret = -500;
    goto err;
  }

check_signature:
  while (0);  // Label followed by a declaration is a C23 extension

  const struct iovec iov[] = {{hm->method.buf, hm->method.len},
                              {hm->uri.buf, hm->uri.len},
                              {hm->body.buf, hm->body.len}};
  size_t msg_len = 0;
  for (size_t i = 0; i < sizeof iov / sizeof *iov; ++i) {
    if (msg_len > SIZE_MAX - iov[i].iov_len) {
      ret = -413;
      goto err;
    }
    msg_len += iov[i].iov_len;
  }
  if ((msg_buf = malloc(msg_len)) == NULL) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    ret = -500;
    goto err;
  }

  size_t i = 0;
  for (uint8_t *p = msg_buf; i < sizeof iov / sizeof *iov;
       p += iov[i++].iov_len)
    memcpy(p, iov[i].iov_base, iov[i].iov_len);

  if (verify_signature(msg_buf, msg_len, (uint8_t *)sig_buf, sig_len, pkey) !=
      1) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    ret = -401;
    goto err;
  }

  ret = 0;

err:
  if (sig_buf) free(sig_buf);
  if (stmt) sqlite3_finalize(stmt);
  if (!supplied_pkey && pkey) EVP_PKEY_free(pkey);
  if (msg_buf) free(msg_buf);
  return ret;
}
