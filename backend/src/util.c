#include "util.h"

#include <crypto.h>
#include <mongoose.h>
#include <sqlite3.h>
#include <sys/types.h>

#include "base64.h"
#include "db.h"

#define ERR(CODE)  \
  do {             \
    ret = -(CODE); \
    goto err;      \
  } while (0)

int64_t verify_request(struct mg_http_message *hm, void **id_key) {
  int64_t ret = -418;
  char *sig_buf = NULL;
  sqlite3_stmt *stmt = NULL;
  uint8_t *msg_buf = NULL;

  struct mg_str *id = mg_http_get_header(hm, "X-Identity");
  struct mg_str *sig_b64 = mg_http_get_header(hm, "X-Signature");
  if (!id || !sig_b64) {
    fprintf(stderr, "[%s:%d] missing required headers\n", __func__, __LINE__);
    ERR(400);
  }

  size_t sig_len = 0;
  sig_buf = b64_decode(sig_b64->buf, sig_b64->len, &sig_len);
  if (!sig_buf || sig_len != XEDDSA_SIGNATURE_LENGTH) {
    fprintf(stderr, "[%s:%d] invalid signature header\n", __func__, __LINE__);
    ERR(400);
  }

  int rc;
  if ((rc = sqlite3_prepare_v3(
           db, "select id, ik from identities where handle = ?;", -1, 0, &stmt,
           NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(500);
  }

  if (sqlite3_bind_text(stmt, 1, id->buf, id->len, SQLITE_STATIC) !=
      SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    ERR(500);
  }

  switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
      break;
    case SQLITE_DONE: {
      fprintf(stderr, "[%s:%d] unknown identity\n", __func__, __LINE__);
      ERR(401);
    }
    default: {
      fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
              sqlite3_errmsg(db));
      ERR(500);
    }
  }

  ret = sqlite3_column_int64(stmt, 0);
  const void *pk_buf = sqlite3_column_blob(stmt, 1);
  int pk_len = sqlite3_column_bytes(stmt, 1);

  if (!pk_buf || pk_len != CURVE25519_PUBLIC_KEY_LENGTH) {
    fprintf(stderr, "[%s:%d] invalid public key buffer\n", __func__, __LINE__);
    ERR(500);
  }

  const struct iovec iov[] = {{hm->method.buf, hm->method.len},
                              {hm->uri.buf, hm->uri.len},
                              {hm->query.buf, hm->query.len},
                              {hm->body.buf, hm->body.len}};
  size_t msg_len = 0;
  for (size_t i = 0; i < sizeof iov / sizeof *iov; ++i) {
    if (msg_len > SIZE_MAX - iov[i].iov_len) ERR(413);
    msg_len += iov[i].iov_len;
  }
  if ((msg_buf = malloc(msg_len)) == NULL) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    ERR(500);
  }

  size_t i = 0;
  for (uint8_t *p = msg_buf; i < sizeof iov / sizeof *iov;
       p += iov[i++].iov_len)
    memcpy(p, iov[i].iov_base, iov[i].iov_len);

  if (!xeddsa_verify(pk_buf, msg_buf, msg_len, (const uint8_t *)sig_buf)) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    ERR(401);
  }

  if (id_key) {
    if ((*id_key = malloc(pk_len)) == NULL) {
      fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
      ERR(500);
    }
    memcpy(*id_key, pk_buf, pk_len);
  }

err:
  if (sig_buf) free(sig_buf);
  if (stmt) sqlite3_finalize(stmt);
  if (msg_buf) free(msg_buf);
  return ret;
}
