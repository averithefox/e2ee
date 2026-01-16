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
  sqlite3_stmt *stmt_identity = NULL, *stmt_pqopk = NULL, *stmt_opk = NULL;
  void *pb_buf = NULL;
  size_t pb_len = 0;

  if (mg_strcmp(hm->method, mg_str("GET")) != 0) ERR(405);

  int64_t _id = verify_request(hm, NULL);
  if (_id < 0) ERR(-_id);

  bool is_dry_run =
      mg_strcmp(mg_http_var(hm->query, mg_str("dryRun")), mg_str("1")) == 0;

  // clang-format off
  const char *sql_identity =
    "select "
      "id,"
      "ik,"
      "spk,"
      "spk_id,"
      "spk_sig,"
      "pqspk,"
      "pqspk_id,"
      "pqspk_sig "
    "from identities where handle = ?;";
  const char *sql_pqopk = "select uid,bytes,id,sig from pqopks where `for` = ? order by uid asc limit 1;";
  const char *sql_opk = "select uid,bytes,id from opks where `for` = ? order by uid asc limit 1;";
  // clang-format on

  int rc;
  if ((rc = sqlite3_prepare_v3(db, sql_identity, -1, 0, &stmt_identity,
                               NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(500);
  }

  if ((rc = sqlite3_bind_text(stmt_identity, 1, handle->buf, handle->len,
                              SQLITE_STATIC)) < 0) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(500);
  }

  switch (rc = sqlite3_step(stmt_identity)) {
    case SQLITE_ROW:
      break;
    case SQLITE_DONE:
      ERR(404);
    default: {
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      ERR(500);
    }
  }

  Messages__PQXDHKeyBundle pb = MESSAGES__PQXDHKEY_BUNDLE__INIT;
  Messages__SignedPrekey spk = MESSAGES__SIGNED_PREKEY__INIT;
  Messages__SignedPrekey pqpk = MESSAGES__SIGNED_PREKEY__INIT;
  Messages__Prekey opk = MESSAGES__PREKEY__INIT;

  pb.id_key.data = (uint8_t *)sqlite3_column_blob(stmt_identity, 1);
  pb.id_key.len = sqlite3_column_bytes(stmt_identity, 1);

  int64_t pqopk_id = -1, opk_id = -1;

  if (!is_dry_run) {
    int64_t id = sqlite3_column_int64(stmt_identity, 0);

    if ((rc = sqlite3_prepare_v3(db, sql_pqopk, -1, 0, &stmt_pqopk, NULL)) !=
            SQLITE_OK ||
        (rc = sqlite3_prepare_v3(db, sql_opk, -1, 0, &stmt_opk, NULL)) !=
            SQLITE_OK) {
      fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__,
              rc, sqlite3_errmsg(db));
      ERR(500);
    }

    if ((rc = sqlite3_bind_int64(stmt_pqopk, 1, id)) != SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt_opk, 1, id)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      ERR(500);
    }

    pb.prekey = &spk;
    spk.key.data = (uint8_t *)sqlite3_column_blob(stmt_identity, 2);
    spk.key.len = sqlite3_column_bytes(stmt_identity, 2);
    spk.id = sqlite3_column_int64(stmt_identity, 3);
    spk.sig.data = (uint8_t *)sqlite3_column_blob(stmt_identity, 4);
    spk.sig.len = sqlite3_column_bytes(stmt_identity, 4);

    pb.pqkem_prekey = &pqpk;
    switch (rc = sqlite3_step(stmt_pqopk)) {
      case SQLITE_ROW: {
        // got a signed one-time pqkem prekey
        pqopk_id = sqlite3_column_int64(stmt_pqopk, 0);
        pqpk.key.data = (uint8_t *)sqlite3_column_blob(stmt_pqopk, 1);
        pqpk.key.len = sqlite3_column_bytes(stmt_pqopk, 1);
        pqpk.id = sqlite3_column_int64(stmt_pqopk, 2);
        pqpk.sig.data = (uint8_t *)sqlite3_column_blob(stmt_pqopk, 3);
        pqpk.sig.len = sqlite3_column_bytes(stmt_pqopk, 3);
        break;
      }
      case SQLITE_DONE: {
        // ran out of signed one-time pqkem prekeys
        pqpk.key.data = (uint8_t *)sqlite3_column_blob(stmt_identity, 5);
        pqpk.key.len = sqlite3_column_bytes(stmt_identity, 5);
        pqpk.id = sqlite3_column_int64(stmt_identity, 6);
        pqpk.sig.data = (uint8_t *)sqlite3_column_blob(stmt_identity, 7);
        pqpk.sig.len = sqlite3_column_bytes(stmt_identity, 7);
        break;
      }
      default: {
        fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__,
                rc, sqlite3_errmsg(db));
        ERR(500);
      }
    }

    switch (rc = sqlite3_step(stmt_opk)) {
      case SQLITE_ROW: {
        // got a one-time curve prekey
        opk_id = sqlite3_column_int64(stmt_opk, 0);
        pb.one_time_prekey = &opk;
        opk.key.data = (uint8_t *)sqlite3_column_blob(stmt_opk, 1);
        opk.key.len = sqlite3_column_bytes(stmt_opk, 1);
        opk.id = sqlite3_column_int64(stmt_opk, 2);
        break;
      }
      case SQLITE_DONE:
        break;
      default: {
        fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__,
                rc, sqlite3_errmsg(db));
        ERR(500);
      }
    }
  }

  pb_len = messages__pqxdhkey_bundle__get_packed_size(&pb);
  pb_buf = malloc(pb_len);
  if (!pb_buf) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    ERR(500);
  }

  messages__pqxdhkey_bundle__pack(&pb, pb_buf);
  mg_printf(c,
            "HTTP/1.1 200 OK\r\n" PREKEY_BUNDLE_REPLY_HEADERS
            "Content-Type: application/protobuf; "
            "proto=messages.PQXDHKeyBundle\r\n"
            "Cache-Control: private, max-age=60\r\n"
            "Content-Length: %d\r\n"
            "\r\n",
            (int)pb_len);
  mg_send(c, pb_buf, pb_len);
  c->is_resp = 0;

  if (stmt_identity) sqlite3_finalize(stmt_identity);
  if (stmt_pqopk) sqlite3_finalize(stmt_pqopk);
  if (stmt_opk) sqlite3_finalize(stmt_opk);

  if (pqopk_id != -1) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "delete from pqopks where uid = ?;";
    if ((rc = sqlite3_prepare_v3(db, sql, -1, 0, &stmt, NULL)) != SQLITE_OK) {
      if ((rc = sqlite3_bind_int64(stmt, 1, pqopk_id)) != SQLITE_OK) {
        if ((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
          fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__,
                  rc, sqlite3_errmsg(db));
        }
      } else {
        fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__,
                rc, sqlite3_errmsg(db));
      }
    } else {
      fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__,
              rc, sqlite3_errmsg(db));
    }
    if (stmt) sqlite3_finalize(stmt);
  }

  if (opk_id != -1) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "delete from opks where uid = ?;";
    if ((rc = sqlite3_prepare_v3(db, sql, -1, 0, &stmt, NULL)) != SQLITE_OK) {
      if ((rc = sqlite3_bind_int64(stmt, 1, opk_id)) != SQLITE_OK) {
        if ((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
          fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__,
                  rc, sqlite3_errmsg(db));
        }
      } else {
        fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__,
                rc, sqlite3_errmsg(db));
      }
    } else {
      fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__,
              rc, sqlite3_errmsg(db));
    }
    if (stmt) sqlite3_finalize(stmt);
  }

  goto end;
err:
  if (stmt_identity) sqlite3_finalize(stmt_identity);
  if (stmt_pqopk) sqlite3_finalize(stmt_pqopk);
  if (stmt_opk) sqlite3_finalize(stmt_opk);
  mg_http_reply(c, status_code, PREKEY_BUNDLE_REPLY_HEADERS, "");
end:
  if (pb_buf) free(pb_buf);
}
