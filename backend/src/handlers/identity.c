#include "handlers/identity.h"

#include <crypto.h>
#include <sqlite3.h>

#include "db.h"
#include "messages.pb-c.h"
#include "mongoose.h"
#include "protobuf-c.h"

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

#define MIN_ONE_TIME_PREKEYS 10

#define BUF(STRUCT) (STRUCT)->data, (STRUCT)->len

static int verify_xeddsa_signature(Messages__SignedBytes *pb,
                                   const uint8_t *pk) {
  if (!pb || !pk) return 0;
  return xeddsa_verify(pk, BUF(&pb->bytes), pb->sig.data);
}

void handle_identity_request(struct mg_connection *c,
                             struct mg_http_message *hm) {
  int status_code = 418;
  Messages__Identity *pb = NULL;
  sqlite3_stmt *stmt0 = NULL, *stmt1 = NULL, *stmt2 = NULL;

  if (mg_strcmp(hm->method, mg_str("POST")) != 0) ERR(405);

  pb = messages__identity__unpack(NULL, hm->body.len, (uint8_t *)hm->body.buf);
  if (!pb) {
    fprintf(stderr, "[%s:%d] invalid message\n", __func__, __LINE__);
    ERR(400);
  }

  Messages__InitPQXDHKeyBundle *kb = pb->key_bundle;
  if (kb->id_key.len != CURVE25519_PUBLIC_KEY_LENGTH ||
      kb->prekey->bytes.len != CURVE25519_PUBLIC_KEY_LENGTH ||
      kb->prekey->sig.len != XEDDSA_SIGNATURE_LENGTH ||
      kb->pqkem_prekey->sig.len != XEDDSA_SIGNATURE_LENGTH ||
      kb->n_one_time_prekeys < MIN_ONE_TIME_PREKEYS ||
      kb->n_one_time_pqkem_prekeys < MIN_ONE_TIME_PREKEYS) {
    fprintf(stderr, "[%s:%d] invalid PQXDH key bundle\n", __func__, __LINE__);
    ERR(400);
  }

  if (!verify_xeddsa_signature(kb->prekey, kb->id_key.data) ||
      !verify_xeddsa_signature(kb->pqkem_prekey, kb->id_key.data)) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    ERR(400);
  }

  for (size_t i = 0; i < kb->n_one_time_pqkem_prekeys; ++i) {
    Messages__SignedBytes *pqopk = kb->one_time_pqkem_prekeys[i];
    if (pqopk->sig.len != XEDDSA_SIGNATURE_LENGTH ||
        !verify_xeddsa_signature(pqopk, kb->id_key.data)) {
      fprintf(stderr, "[%s:%d] invalid signature for PQOPK at [%zu]\n",
              __func__, __LINE__, i);
      ERR(400);
    }
  }

  // clang-format off
  const char* sql0 =
    "insert or ignore into identities("
      "handle,"
      "ik,"
      "spk,"
      "spk_sig,"
      "pqspk,"
      "pqspk_sig"
    ")values(?,?,?,?,?,?);";
  const char* sql1 = "insert into pqopks (for,bytes,sig) values (?,?,?);";
  const char* sql2 = "insert into opks (for,bytes) values (?,?,?);";
  // clang-format on

  if (sqlite3_prepare_v3(db, sql0, -1, 0, &stmt0, NULL) < 0 ||
      sqlite3_prepare_v3(db, sql1, -1, 0, &stmt1, NULL) < 0 ||
      sqlite3_prepare_v3(db, sql2, -1, 0, &stmt2, NULL) < 0) {
    fprintf(stderr, "[%s:%d] prepare failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    ERR(500);
  }

  if (sqlite3_exec(db, "begin transaction;", NULL, NULL, NULL) < 0) {
    fprintf(stderr, "[%s:%d] begin transaction failed: %s\n", __func__,
            __LINE__, sqlite3_errmsg(db));
    ERR(500);
  }

  if (sqlite3_bind_text(stmt0, 1, pb->handle, -1, SQLITE_STATIC) < 0 ||
      sqlite3_bind_blob(stmt0, 2, BUF(&kb->id_key), SQLITE_STATIC) < 0 ||
      sqlite3_bind_blob(stmt0, 3, BUF(&kb->prekey->bytes), SQLITE_STATIC) < 0 ||
      sqlite3_bind_blob(stmt0, 4, BUF(&kb->prekey->sig), SQLITE_STATIC) < 0 ||
      sqlite3_bind_blob(stmt0, 5, BUF(&kb->pqkem_prekey->bytes),
                        SQLITE_STATIC) < 0 ||
      sqlite3_bind_blob(stmt0, 6, BUF(&kb->pqkem_prekey->sig), SQLITE_STATIC) <
          0) {
    fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
    ERR(500);
  }

  if (sqlite3_step(stmt0) != SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
    ERR(500);
  }

  if (sqlite3_changes(db) == 0) {
    sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
    ERR(409);
  }
  int64_t id = sqlite3_last_insert_rowid(db);

  for (size_t i = 0; i < kb->n_one_time_pqkem_prekeys; ++i) {
    Messages__SignedBytes *pqopk = kb->one_time_pqkem_prekeys[i];

    if (sqlite3_bind_int64(stmt1, 1, id) < 0 ||
        sqlite3_bind_blob(stmt1, 2, BUF(&pqopk->bytes), SQLITE_STATIC) < 0 ||
        sqlite3_bind_blob(stmt1, 3, BUF(&pqopk->sig), SQLITE_STATIC) < 0) {
      fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
              sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    if (sqlite3_step(stmt1) != SQLITE_DONE) {
      fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
              sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    sqlite3_reset(stmt1);
    sqlite3_clear_bindings(stmt1);
  }

  for (size_t i = 0; i < kb->n_one_time_prekeys; ++i) {
    ProtobufCBinaryData *opk = &kb->one_time_prekeys[i];

    if (sqlite3_bind_int64(stmt2, 1, id) < 0 ||
        sqlite3_bind_blob(stmt2, 2, BUF(opk), SQLITE_STATIC) < 0) {
      fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
              sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    if (sqlite3_step(stmt2) != SQLITE_DONE) {
      fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
              sqlite3_errmsg(db));
      sqlite3_exec(db, "rollback;", NULL, NULL, NULL);
      ERR(500);
    }

    sqlite3_reset(stmt2);
    sqlite3_clear_bindings(stmt2);
  }

  if (sqlite3_exec(db, "commit;", NULL, NULL, NULL) < 0) {
    fprintf(stderr, "[%s:%d] commit failed: %s\n", __func__, __LINE__,
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
