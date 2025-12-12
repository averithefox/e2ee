#include "handlers/get_identity.h"

#include <sqlite3.h>

#include "db.h"
#include "messages.pb-c.h"
#include "util.h"

#ifndef NDEBUG
#define GET_IDENTITY_REPLY_HEADERS "Access-Control-Allow-Origin: *\r\n"
#else
#define GET_IDENTITY_REPLY_HEADERS ""
#endif

void handle_get_identity_request(struct mg_connection *c,
                                 struct mg_http_message *hm) {
  int status_code = 418;
  sqlite3_stmt *stmt = NULL;
  void *pb_buf = NULL;
  size_t pb_len = 0;

  int err = verify_request(hm, NULL);
  if (err < 0) {
    status_code = -err;
    goto err;
  }

  struct mg_str handle_var = mg_http_var(hm->query, mg_str("handle"));
  if (!handle_var.buf || !handle_var.len) {
    status_code = 400;
    goto err;
  }

  if (sqlite3_prepare_v3(db,
                         "select handle, encryption_key, signing_key from "
                         "identities where handle = ?;",
                         -1, 0, &stmt, NULL) < 0) {
    fprintf(stderr, "[%s:%d] prepare failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    status_code = 500;
    goto err;
  }

  if (sqlite3_bind_text(stmt, 1, handle_var.buf, handle_var.len,
                        SQLITE_STATIC) < 0) {
    fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    status_code = 500;
    goto err;
  }

  err = sqlite3_step(stmt);
  if (err == SQLITE_DONE) {
    status_code = 404;
    goto err;
  }

  if (err != SQLITE_ROW) {
    fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    status_code = 500;
    goto err;
  }

  char *handle = (char *)sqlite3_column_text(stmt, 0);
  void *enc_key_buf = (void *)sqlite3_column_blob(stmt, 1);
  size_t enc_key_len = sqlite3_column_bytes(stmt, 1);
  void *sig_key_buf = (void *)sqlite3_column_blob(stmt, 2);
  size_t sig_key_len = sqlite3_column_bytes(stmt, 2);

  Messages__Identity pb = MESSAGES__IDENTITY__INIT;
  pb.username = handle;
  pb.pub_enc_key.data = enc_key_buf;
  pb.pub_enc_key.len = enc_key_len;
  pb.pub_sig_key.data = sig_key_buf;
  pb.pub_sig_key.len = sig_key_len;

  pb_len = messages__identity__get_packed_size(&pb);
  if ((pb_buf = malloc(pb_len)) == NULL) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    status_code = 500;
    goto err;
  }

  messages__identity__pack(&pb, pb_buf);

  status_code = 200;

err:
  if (stmt) sqlite3_finalize(stmt);
  if (pb_buf) {
    mg_http_reply(
        c, status_code,
        GET_IDENTITY_REPLY_HEADERS
        "Content-Type: application/protobuf; proto=messages.Identity\r\n"
        "Cache-Control: private, max-age=60\r\n",
        "%.*s", pb_len, pb_buf);
    free(pb_buf);
  } else {
    mg_http_reply(c, status_code, GET_IDENTITY_REPLY_HEADERS, "");
  }
}
