#include "handlers/prekey_bundle.h"

#include <sqlite3.h>

#include "db.h"
#include "messages.pb-c.h"
#include "util.h"

#ifndef NDEBUG
#define PREKEY_BUNDLE_REPLY_HEADERS "Access-Control-Allow-Origin: *\r\n"
#else
#define PREKEY_BUNDLE_REPLY_HEADERS ""
#endif

#define ERR(CODE)         \
  do {                    \
    status_code = (CODE); \
    goto err;             \
  } while (0)

void handle_prekey_bundle_request(struct mg_connection *c,
                                  struct mg_http_message *hm,
                                  struct mg_str *handle) {
  int status_code = 418;
  sqlite3_stmt *stmt0 = NULL, *stmt1 = NULL, *stmt2 = NULL;
  void *pb_buf = NULL;
  size_t pb_len = 0;

  int64_t _id = verify_request(hm);
  if (_id < 0) ERR(-_id);

  // clang-format off
  const char* sql0 =
    "select "
      "id,"
      "ik,"
      "spk,"
      "spk_sig,"
      "pqspk,"
      "pqspk_sig "
    "from identities where handle = ?;";
  const char* sql1 = "select id, bytes, sig from pqopks where for = ? and used = 0 order by id asc limit 1;";
  const char* sql2 = "select id, bytes from opks where for = ? and used = 0 order by id asc limit 1;";
  // clang-format on

  if (sqlite3_prepare_v3(db, sql0, -1, 0, &stmt0, NULL) < 0) {
  prepare_fail:
    fprintf(stderr, "[%s:%d] prepare failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    ERR(500);
  }

  if (sqlite3_bind_text(stmt0, 1, handle->buf, handle->len, SQLITE_STATIC) <
      0) {
  bind_fail:
    fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    ERR(500);
  }

  int rc = sqlite3_step(stmt0);
  switch (rc) {
    case SQLITE_ROW:
      break;
    case SQLITE_DONE:
      ERR(404);
    default: {
    step_fail:
      fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
              sqlite3_errmsg(db));
      ERR(500);
    }
  }

  int64_t id = sqlite3_column_int64(stmt0, 0);

  if (sqlite3_prepare_v3(db, sql1, -1, 0, &stmt1, NULL) < 0 ||
      sqlite3_prepare_v3(db, sql2, -1, 0, &stmt2, NULL) < 0)
    goto prepare_fail;

  if (sqlite3_bind_int64(stmt1, 1, id) < 0 ||
      sqlite3_bind_int64(stmt2, 1, id) < 0)
    goto bind_fail;

  Messages__PQXDHKeyBundle pb = MESSAGES__PQXDHKEY_BUNDLE__INIT;
  Messages__SignedBytes spk = MESSAGES__SIGNED_BYTES__INIT;
  Messages__SignedBytes pqpk = MESSAGES__SIGNED_BYTES__INIT;

  pb.prekey = &spk;
  pb.pqkem_prekey = &pqpk;

  pb.id_key.data = (uint8_t *)sqlite3_column_blob(stmt0, 1);
  pb.id_key.len = sqlite3_column_bytes(stmt0, 1);

  spk.bytes.data = (uint8_t *)sqlite3_column_blob(stmt0, 2);
  spk.bytes.len = sqlite3_column_bytes(stmt0, 2);
  spk.sig.data = (uint8_t *)sqlite3_column_blob(stmt0, 3);
  spk.sig.len = sqlite3_column_bytes(stmt0, 3);

  int64_t pqopk_id = -1, opk_id = -1;

  rc = sqlite3_step(stmt1);
  switch (rc) {
    case SQLITE_ROW: {
      // got a signed one-time pqkem prekey
      pqopk_id = sqlite3_column_int64(stmt1, 0);
      pqpk.bytes.data = (uint8_t *)sqlite3_column_blob(stmt1, 1);
      pqpk.bytes.len = sqlite3_column_bytes(stmt1, 1);
      pqpk.sig.data = (uint8_t *)sqlite3_column_blob(stmt1, 2);
      pqpk.sig.len = sqlite3_column_bytes(stmt1, 2);
      break;
    }
    case SQLITE_DONE: {
      // ran out of signed one-time pqkem prekeys
      pqpk.bytes.data = (uint8_t *)sqlite3_column_blob(stmt0, 4);
      pqpk.bytes.len = sqlite3_column_bytes(stmt0, 4);
      pqpk.sig.data = (uint8_t *)sqlite3_column_blob(stmt0, 5);
      pqpk.sig.len = sqlite3_column_bytes(stmt0, 5);
      break;
    }
    default:
      goto step_fail;
  }

  rc = sqlite3_step(stmt2);
  switch (rc) {
    case SQLITE_ROW: {
      // got a one-time curve prekey
      opk_id = sqlite3_column_int64(stmt2, 0);
      pb.has_one_time_prekey = 1;
      pb.one_time_prekey.data = (uint8_t *)sqlite3_column_blob(stmt2, 1);
      pb.one_time_prekey.len = sqlite3_column_bytes(stmt2, 1);
      break;
    }
    case SQLITE_DONE:
      break;
    default:
      goto step_fail;
  }

  pb_len = messages__pqxdhkey_bundle__get_packed_size(&pb);
  pb_buf = malloc(pb_len);
  if (!pb_buf) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    ERR(500);
  }

  messages__pqxdhkey_bundle__pack(&pb, pb_buf);
  mg_http_reply(c, 200,
                PREKEY_BUNDLE_REPLY_HEADERS
                "Content-Type: application/protobuf; "
                "proto=messages.PQXDHKeyBundle\r\n"
                "Cache-Control: private, max-age=60\r\n",
                "%.*s", pb_len, pb_buf);

  if (stmt0) sqlite3_finalize(stmt0);
  if (stmt1) sqlite3_finalize(stmt1);
  if (stmt2) sqlite3_finalize(stmt2);

  if (pqopk_id != -1) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "update pqopks set used = 1 where id = ?;";
    if (sqlite3_prepare_v3(db, sql, -1, 0, &stmt, NULL) >= 0) {
      if (sqlite3_bind_int64(stmt, 1, pqopk_id) >= 0) {
        if (sqlite3_step(stmt) != SQLITE_DONE) {
          fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
                  sqlite3_errmsg(db));
        }
      } else {
        fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
                sqlite3_errmsg(db));
      }
    } else {
      fprintf(stderr, "[%s:%d] prepare failed: %s\n", __func__, __LINE__,
              sqlite3_errmsg(db));
    }
    if (stmt) sqlite3_finalize(stmt);
  }

  if (opk_id != -1) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "update opks set used = 1 where id = ?;";
    if (sqlite3_prepare_v3(db, sql, -1, 0, &stmt, NULL) >= 0) {
      if (sqlite3_bind_int64(stmt, 1, opk_id) >= 0) {
        if (sqlite3_step(stmt) != SQLITE_DONE) {
          fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
                  sqlite3_errmsg(db));
        }
      } else {
        fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
                sqlite3_errmsg(db));
      }
    } else {
      fprintf(stderr, "[%s:%d] prepare failed: %s\n", __func__, __LINE__,
              sqlite3_errmsg(db));
    }
    if (stmt) sqlite3_finalize(stmt);
  }

  goto end;
err:
  if (stmt0) sqlite3_finalize(stmt0);
  if (stmt1) sqlite3_finalize(stmt1);
  if (stmt2) sqlite3_finalize(stmt2);
  mg_http_reply(c, status_code, PREKEY_BUNDLE_REPLY_HEADERS, "");
end:
  if (pb_buf) free(pb_buf);
}
