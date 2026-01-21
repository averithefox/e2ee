#include "handlers/identity.h"

#include <crypto.h>
#include <sqlite3.h>

#include "db.h"
#include "messages.pb-c.h"
#include "mongoose.h"
#include "protobuf-c.h"
#include "util.h"

#ifndef NDEBUG
#define NEW_IDENTITY_REPLY_HEADERS "Access-Control-Allow-Origin: *\r\n"
#else
#define NEW_IDENTITY_REPLY_HEADERS ""
#endif

#define ERR(CODE)         \
  do {                    \
    status_code = (CODE); \
    goto err;             \
  } while (0)

#define BUF(STRUCT) (STRUCT).data, (STRUCT).len

#define HANDLE_MIN_LENGTH 3
#define HANDLE_MAX_LENGTH 32

static int validate_handle(const char *handle) {
  if (!handle) return 0;

  size_t len = strlen(handle);
  if (len < HANDLE_MIN_LENGTH || len > HANDLE_MAX_LENGTH) return 0;

  // Must start with a lowercase letter
  if (!islower((unsigned char)handle[0])) return 0;

  for (size_t i = 0; i < len; ++i) {
    char c = handle[i];
    // Must be lowercase letter, digit, or underscore
    if (!islower((unsigned char)c) && !isdigit((unsigned char)c) && c != '_')
      return 0;
    // No consecutive underscores
    if (c == '_' && i > 0 && handle[i - 1] == '_') return 0;
  }

  // Cannot end with underscore
  if (handle[len - 1] == '_') return 0;

  return 1;
}

static int verify_xeddsa_signature(const Messages__SignedPrekey *pb,
                                   const void *pk) {
  if (!pb || pb->sig.len != XEDDSA_SIGNATURE_LENGTH || !pk) return 0;
  return xeddsa_verify(pk, BUF(pb->key), pb->sig.data);
}

static void handle_identity_POST_request(struct mg_connection *c,
                                         struct mg_http_message *hm) {
  int status_code = 418;
  Messages__Identity *pb = NULL;
  sqlite3_stmt *stmt0 = NULL, *stmt1 = NULL, *stmt2 = NULL;

  pb = messages__identity__unpack(NULL, hm->body.len, (uint8_t *)hm->body.buf);
  if (!pb) {
    fprintf(stderr, "[%s:%d] invalid message\n", __func__, __LINE__);
    ERR(400);
  }

  if (!validate_handle(pb->handle)) {
    fprintf(stderr, "[%s:%d] invalid handle: %s\n", __func__, __LINE__,
            pb->handle);
    ERR(400);
  }

  if (pb->id_key.len != CURVE25519_PUBLIC_KEY_LENGTH ||
      pb->prekey->key.len != CURVE25519_PUBLIC_KEY_LENGTH) {
    fprintf(stderr, "[%s:%d] invalid key\n", __func__, __LINE__);
    ERR(400);
  }

  if (!verify_xeddsa_signature(pb->prekey, pb->id_key.data) ||
      !verify_xeddsa_signature(pb->pqkem_prekey, pb->id_key.data)) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    ERR(400);
  }

  for (size_t i = 0; i < pb->n_one_time_pqkem_prekeys; ++i) {
    if (!verify_xeddsa_signature(pb->one_time_pqkem_prekeys[i],
                                 pb->id_key.data)) {
      fprintf(stderr, "[%s:%d] invalid signature for PQOPK at [%zu]\n",
              __func__, __LINE__, i);
      ERR(400);
    }
  }

  // clang-format off
  const char *sql0 =
    "insert or ignore into identities("
      "handle,"
      "ik,"
      "spk,"
      "spk_id,"
      "spk_sig,"
      "pqspk,"
      "pqspk_id,"
      "pqspk_sig"
    ")values(?,?,?,?,?,?,?,?);";
  const char *sql1 = "insert into pqopks(for,bytes,id,sig)values(?,?,?,?);";
  const char *sql2 = "insert into opks(for,bytes,id)values(?,?,?);";
  // clang-format on

  int rc;
  if ((rc = sqlite3_prepare_v3(db, sql0, -1, 0, &stmt0, NULL)) != SQLITE_OK ||
      (rc = sqlite3_prepare_v3(db, sql1, -1, 0, &stmt1, NULL)) != SQLITE_OK ||
      (rc = sqlite3_prepare_v3(db, sql2, -1, 0, &stmt2, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(500);
  }

  if ((rc = sqlite3_exec(db, "begin transaction;", NULL, NULL, NULL)) !=
      SQLITE_OK) {
    fprintf(stderr, "[%s:%d] begin transaction failed: %d (%s)\n", __func__,
            __LINE__, rc, sqlite3_errmsg(db));
    ERR(500);
  }

  if ((rc = sqlite3_bind_text(stmt0, 1, pb->handle, -1, SQLITE_STATIC)) !=
          SQLITE_OK ||
      (rc = sqlite3_bind_blob(stmt0, 2, BUF(pb->id_key), SQLITE_STATIC)) !=
          SQLITE_OK ||
      (rc = sqlite3_bind_blob(stmt0, 3, BUF(pb->prekey->key), SQLITE_STATIC)) !=
          SQLITE_OK ||
      (rc = sqlite3_bind_int64(stmt0, 4, pb->prekey->id)) != SQLITE_OK ||
      (rc = sqlite3_bind_blob(stmt0, 5, BUF(pb->prekey->sig), SQLITE_STATIC)) !=
          SQLITE_OK ||
      (rc = sqlite3_bind_blob(stmt0, 6, BUF(pb->pqkem_prekey->key),
                              SQLITE_STATIC)) != SQLITE_OK ||
      (rc = sqlite3_bind_int64(stmt0, 7, pb->pqkem_prekey->id)) != SQLITE_OK ||
      (rc = sqlite3_bind_blob(stmt0, 8, BUF(pb->pqkem_prekey->sig),
                              SQLITE_STATIC)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
    ERR(500);
  }

  if ((rc = sqlite3_step(stmt0)) != SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
    ERR(500);
  }

  if (sqlite3_changes(db) == 0) {
    sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
    ERR(409);
  }
  int64_t id = sqlite3_last_insert_rowid(db);

  for (size_t i = 0; i < pb->n_one_time_pqkem_prekeys; ++i) {
    Messages__SignedPrekey *pqopk = pb->one_time_pqkem_prekeys[i];

    if ((rc = sqlite3_bind_int64(stmt1, 1, id)) != SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt1, 2, BUF(pqopk->key), SQLITE_STATIC)) !=
            SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt1, 3, pqopk->id)) != SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt1, 4, BUF(pqopk->sig), SQLITE_STATIC)) !=
            SQLITE_OK) {
      fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    if ((rc = sqlite3_step(stmt1)) != SQLITE_DONE) {
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    sqlite3_reset(stmt1);
    sqlite3_clear_bindings(stmt1);
  }

  for (size_t i = 0; i < pb->n_one_time_prekeys; ++i) {
    Messages__Prekey *opk = pb->one_time_prekeys[i];

    if ((rc = sqlite3_bind_int64(stmt2, 1, id)) != SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt2, 2, BUF(opk->key), SQLITE_STATIC)) !=
            SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt2, 3, opk->id)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    if ((rc = sqlite3_step(stmt2)) != SQLITE_DONE) {
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    sqlite3_reset(stmt2);
    sqlite3_clear_bindings(stmt2);
  }

  if ((rc = sqlite3_exec(db, "commit;", NULL, NULL, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] commit failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(500);
  }

  status_code = 201;

err:
  if (pb) messages__identity__free_unpacked(pb, NULL);
  if (stmt0) sqlite3_finalize(stmt0);
  if (stmt1) sqlite3_finalize(stmt1);
  if (stmt2) sqlite3_finalize(stmt2);
  mg_http_reply(c, status_code, NEW_IDENTITY_REPLY_HEADERS, "");
}

static void handle_identity_PATCH_request(struct mg_connection *c,
                                          struct mg_http_message *hm) {
  int status_code = 418;
  void *id_key = NULL;
  Messages__IdentityPatch *pb = NULL;
  sqlite3_stmt *stmt_update = NULL, *stmt_insert_pqopk = NULL,
               *stmt_insert_opk = NULL;

  int64_t id = verify_request(hm, &id_key);
  if (id < 0) ERR(-id);

  pb = messages__identity_patch__unpack(NULL, hm->body.len,
                                        (uint8_t *)hm->body.buf);
  if (!pb) {
    fprintf(stderr, "[%s:%d] invalid message\n", __func__, __LINE__);
    ERR(400);
  }

  if (pb->prekey && pb->prekey->key.len != CURVE25519_PUBLIC_KEY_LENGTH) {
    fprintf(stderr, "[%s:%d] invalid prekey\n", __func__, __LINE__);
    ERR(400);
  }

  if ((pb->prekey && !verify_xeddsa_signature(pb->prekey, id_key)) ||
      (pb->pqkem_prekey &&
       !verify_xeddsa_signature(pb->pqkem_prekey, id_key))) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    ERR(400);
  }

  for (size_t i = 0; i < pb->n_one_time_pqkem_prekeys; ++i) {
    if (!verify_xeddsa_signature(pb->one_time_pqkem_prekeys[i], id_key)) {
      fprintf(stderr, "[%s:%d] invalid signature for PQOPK at [%zu]\n",
              __func__, __LINE__, i);
      ERR(400);
    }
  }

  // clang-format off
  const char *sql_update = "update identities set spk=?,spk_id=?,spk_sig=?,pqspk=?,pqspk_id=?,pqspk_sig=? where id=?;";
  const char *sql_update_spk_only = "update identities set spk=?,spk_id=?,spk_sig=? where id=?;";
  const char *sql_update_pqspk_only = "update identities set pqspk=?,pqspk_id=?,pqspk_sig=? where id=?;";
  const char *sql_insert_pqopk = "insert into pqopks(for,bytes,id,sig)values(?,?,?,?);";
  const char *sql_insert_opk = "insert into opks(for,bytes,id)values(?,?,?);";
  // clang-format on

  int rc;
  if (pb->prekey && pb->pqkem_prekey) {
    if ((rc = sqlite3_prepare_v3(db, sql_update, -1, 0, &stmt_update, NULL)) !=
        SQLITE_OK) {
      fprintf(stderr, "[%s:%d] prepare update failed: %d (%s)\n", __func__,
              __LINE__, rc, sqlite3_errmsg(db));
      ERR(500);
    }
  } else if (pb->prekey) {
    if ((rc = sqlite3_prepare_v3(db, sql_update_spk_only, -1, 0, &stmt_update,
                                 NULL)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] prepare update spk failed: %d (%s)\n", __func__,
              __LINE__, rc, sqlite3_errmsg(db));
      ERR(500);
    }
  } else if (pb->pqkem_prekey) {
    if ((rc = sqlite3_prepare_v3(db, sql_update_pqspk_only, -1, 0, &stmt_update,
                                 NULL)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] prepare update pqspk failed: %d (%s)\n",
              __func__, __LINE__, rc, sqlite3_errmsg(db));
      ERR(500);
    }
  }

  if ((rc = sqlite3_exec(db, "begin transaction;", NULL, NULL, NULL)) !=
      SQLITE_OK) {
    fprintf(stderr, "[%s:%d] begin transaction failed: %d (%s)\n", __func__,
            __LINE__, rc, sqlite3_errmsg(db));
    ERR(500);
  }

  if (pb->prekey && pb->pqkem_prekey) {
    if ((rc = sqlite3_bind_blob(stmt_update, 1, BUF(pb->prekey->key),
                                SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt_update, 2, pb->prekey->id)) !=
            SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt_update, 3, BUF(pb->prekey->sig),
                                SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt_update, 4, BUF(pb->pqkem_prekey->key),
                                SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt_update, 5, pb->pqkem_prekey->id)) !=
            SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt_update, 6, BUF(pb->pqkem_prekey->sig),
                                SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt_update, 7, id)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] bind update failed: %d (%s)\n", __func__,
              __LINE__, rc, sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }
  } else if (pb->prekey) {
    if ((rc = sqlite3_bind_blob(stmt_update, 1, BUF(pb->prekey->key),
                                SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt_update, 2, pb->prekey->id)) !=
            SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt_update, 3, BUF(pb->prekey->sig),
                                SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt_update, 4, id)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] bind update spk failed: %d (%s)\n", __func__,
              __LINE__, rc, sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }
  } else if (pb->pqkem_prekey) {
    if ((rc = sqlite3_bind_blob(stmt_update, 1, BUF(pb->pqkem_prekey->key),
                                SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt_update, 2, pb->pqkem_prekey->id)) !=
            SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt_update, 3, BUF(pb->pqkem_prekey->sig),
                                SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_int64(stmt_update, 4, id)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] bind update pqspk failed: %d (%s)\n", __func__,
              __LINE__, rc, sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }
  }

  if (stmt_update) {
    if ((rc = sqlite3_step(stmt_update)) != SQLITE_DONE) {
      fprintf(stderr, "[%s:%d] step update failed: %d (%s)\n", __func__,
              __LINE__, rc, sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }
  }

  if (pb->n_one_time_pqkem_prekeys > 0) {
    if ((rc = sqlite3_prepare_v3(db, sql_insert_pqopk, -1, 0,
                                 &stmt_insert_pqopk, NULL)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] prepare insert pqopk failed: %d (%s)\n",
              __func__, __LINE__, rc, sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    for (size_t i = 0; i < pb->n_one_time_pqkem_prekeys; ++i) {
      Messages__SignedPrekey *pqopk = pb->one_time_pqkem_prekeys[i];

      if ((rc = sqlite3_bind_int64(stmt_insert_pqopk, 1, id)) != SQLITE_OK ||
          (rc = sqlite3_bind_blob(stmt_insert_pqopk, 2, BUF(pqopk->key),
                                  SQLITE_STATIC)) != SQLITE_OK ||
          (rc = sqlite3_bind_int64(stmt_insert_pqopk, 3, pqopk->id)) !=
              SQLITE_OK ||
          (rc = sqlite3_bind_blob(stmt_insert_pqopk, 4, BUF(pqopk->sig),
                                  SQLITE_STATIC)) != SQLITE_OK) {
        fprintf(stderr, "[%s:%d] bind insert pqopk failed: %d (%s)\n", __func__,
                __LINE__, rc, sqlite3_errmsg(db));
        sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
        ERR(500);
      }

      if ((rc = sqlite3_step(stmt_insert_pqopk)) != SQLITE_DONE) {
        fprintf(stderr, "[%s:%d] step insert pqopk failed: %d (%s)\n", __func__,
                __LINE__, rc, sqlite3_errmsg(db));
        sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
        ERR(500);
      }

      sqlite3_reset(stmt_insert_pqopk);
      sqlite3_clear_bindings(stmt_insert_pqopk);
    }
  }

  if (pb->n_one_time_prekeys > 0) {
    if ((rc = sqlite3_prepare_v3(db, sql_insert_opk, -1, 0, &stmt_insert_opk,
                                 NULL)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] prepare insert opk failed: %d (%s)\n", __func__,
              __LINE__, rc, sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    for (size_t i = 0; i < pb->n_one_time_prekeys; ++i) {
      Messages__Prekey *opk = pb->one_time_prekeys[i];

      if ((rc = sqlite3_bind_int64(stmt_insert_opk, 1, id)) != SQLITE_OK ||
          (rc = sqlite3_bind_blob(stmt_insert_opk, 2, BUF(opk->key),
                                  SQLITE_STATIC)) != SQLITE_OK ||
          (rc = sqlite3_bind_int64(stmt_insert_opk, 3, opk->id)) != SQLITE_OK) {
        fprintf(stderr, "[%s:%d] bind insert opk failed: %d (%s)\n", __func__,
                __LINE__, rc, sqlite3_errmsg(db));
        sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
        ERR(500);
      }

      if ((rc = sqlite3_step(stmt_insert_opk)) != SQLITE_DONE) {
        fprintf(stderr, "[%s:%d] step insert opk failed: %d (%s)\n", __func__,
                __LINE__, rc, sqlite3_errmsg(db));
        sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
        ERR(500);
      }

      sqlite3_reset(stmt_insert_opk);
      sqlite3_clear_bindings(stmt_insert_opk);
    }
  }

  if ((rc = sqlite3_exec(db, "commit;", NULL, NULL, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] commit failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(500);
  }

  mg_http_reply(c, 200, NEW_IDENTITY_REPLY_HEADERS, "");

  if (pb->n_one_time_pqkem_prekeys > 0 || pb->n_one_time_prekeys > 0) {
    sqlite3_stmt *stmt = NULL;

    const char *sql =
        "update identities set notified_low_prekeys=0 where id=?;";

    if ((rc = sqlite3_prepare_v3(db, sql, -1, 0, &stmt, NULL)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__,
              rc, sqlite3_errmsg(db));
      goto notif_ack_err;
    }

    if ((rc = sqlite3_bind_int64(stmt, 1, id)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      goto notif_ack_err;
    }

    if ((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      goto notif_ack_err;
    }

  notif_ack_err:
    if (stmt) sqlite3_finalize(stmt);
  }

  goto cleanup;
err:
  mg_http_reply(c, status_code, NEW_IDENTITY_REPLY_HEADERS, "");
cleanup:
  if (id_key) free(id_key);
  if (pb) messages__identity_patch__free_unpacked(pb, NULL);
  if (stmt_update) sqlite3_finalize(stmt_update);
  if (stmt_insert_pqopk) sqlite3_finalize(stmt_insert_pqopk);
  if (stmt_insert_opk) sqlite3_finalize(stmt_insert_opk);
}

static void handle_identity_DELETE_request(struct mg_connection *c,
                                           struct mg_http_message *hm) {
  int status_code = 418;
  sqlite3_stmt *stmt = NULL;

  int64_t id = verify_request(hm, NULL);
  if (id < 0) ERR(-id);

  int rc;
  if ((rc = sqlite3_prepare_v3(db, "delete from identities where id=?;", -1, 0,
                               &stmt, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(500);
  }

  if ((rc = sqlite3_bind_int64(stmt, 1, id)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(500);
  }

  if ((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(500);
  }

  status_code = 200;

err:
  if (stmt) sqlite3_finalize(stmt);
  mg_http_reply(c, status_code, NEW_IDENTITY_REPLY_HEADERS, "");
}

void handle_identity_request(struct mg_connection *c,
                             struct mg_http_message *hm) {
  if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
    handle_identity_POST_request(c, hm);
  } else if (mg_strcmp(hm->method, mg_str("PATCH")) == 0) {
    handle_identity_PATCH_request(c, hm);
  } else if (mg_strcmp(hm->method, mg_str("DELETE")) == 0) {
    handle_identity_DELETE_request(c, hm);
  } else {
    mg_http_reply(c, 405, NEW_IDENTITY_REPLY_HEADERS, "");
  }
}
