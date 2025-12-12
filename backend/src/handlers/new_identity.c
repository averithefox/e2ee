#include "handlers/new_identity.h"

#include <sqlite3.h>

#include "db.h"
#include "messages.pb-c.h"
#include "mongoose.h"
#include "util.h"

#ifndef NDEBUG
#define NEW_IDENTITY_REPLY_HEADERS "Access-Control-Allow-Origin: *\r\n"
#else
#define NEW_IDENTITY_REPLY_HEADERS ""
#endif

void handle_new_identity_request(struct mg_connection *c,
                                 struct mg_http_message *hm) {
  int status_code = 418;
  char *sig_buf = NULL;
  Messages__Identity *id_pb = NULL;
  EVP_PKEY *sig_key = NULL, *enc_key = NULL;
  sqlite3_stmt *stmt = NULL;

  if (mg_strcmp(hm->method, mg_str("POST")) != 0) {
    status_code = 405;
    goto err;
  }

  id_pb =
      messages__identity__unpack(NULL, hm->body.len, (uint8_t *)hm->body.buf);
  if (!id_pb) {
    fprintf(stderr, "[%s:%d] invalid message\n", __func__, __LINE__);
    status_code = 400;
    goto err;
  }

  if ((sig_key = load_pub_sig_key_from_spki(id_pb->pub_sig_key.data,
                                            id_pb->pub_sig_key.len)) == NULL)
    goto err;

  int err = verify_request(hm, sig_key);
  if (err < 0) {
    status_code = -err;
    goto err;
  }

  if ((enc_key = load_pub_enc_key_from_spki(id_pb->pub_enc_key.data,
                                            id_pb->pub_enc_key.len)) == NULL)
    goto err;

  if (sqlite3_prepare_v3(db,
                         "insert or ignore into identities (handle,"
                         "encryption_key,signing_key) values (?,?,?);",
                         -1, 0, &stmt, NULL) < 0) {
    fprintf(stderr, "[%s:%d] prepare failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    status_code = 500;
    goto err;
  }

  if (sqlite3_bind_text(stmt, 1, id_pb->username, -1, SQLITE_STATIC) < 0 ||
      sqlite3_bind_blob(stmt, 2, id_pb->pub_enc_key.data,
                        id_pb->pub_enc_key.len, SQLITE_STATIC) < 0 ||
      sqlite3_bind_blob(stmt, 3, id_pb->pub_sig_key.data,
                        id_pb->pub_sig_key.len, SQLITE_STATIC) < 0) {
    fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    status_code = 500;
    goto err;
  }

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    status_code = 500;
    goto err;
  }

  status_code = sqlite3_changes(db) == 0 ? 409 : 201;

err:
  if (sig_buf) free(sig_buf);
  if (id_pb) messages__identity__free_unpacked(id_pb, NULL);
  if (sig_key) EVP_PKEY_free(sig_key);
  if (enc_key) EVP_PKEY_free(enc_key);
  if (stmt) sqlite3_finalize(stmt);
  mg_http_reply(c, status_code, NEW_IDENTITY_REPLY_HEADERS, "");
}
