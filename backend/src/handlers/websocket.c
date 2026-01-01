#include "handlers/websocket.h"

#include <crypto.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include "db.h"
#include "mongoose.h"
#include "websocket.pb-c.h"

#define OPK_CNT_WARNING_THRESHOLD 10

void handle_ws_upgrade_request(struct mg_connection *c,
                               struct mg_http_message *hm) {
  mg_ws_upgrade(c, hm, NULL);
}

void handle_ws_open(struct mg_connection *c, struct mg_http_message *hm) {
  (void)hm;

  struct ws_ctx *ctx = malloc(sizeof(struct ws_ctx));
  if (!ctx) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    goto err;
  }
  // freeing the ctx is taken care of by MG_EV_CLOSE handler
  c->fn_data = ctx;

  ctx->id = -1;
  if (RAND_bytes(ctx->nonce, sizeof ctx->nonce) != 1) goto err;

  Websocket__Challenge ch = WEBSOCKET__CHALLENGE__INIT;
  ch.nonce.data = ctx->nonce;
  ch.nonce.len = sizeof ctx->nonce;

  Websocket__Envelope env = WEBSOCKET__ENVELOPE__INIT;
  env.payload_case = WEBSOCKET__ENVELOPE__PAYLOAD_CHALLENGE;
  env.challenge = &ch;

  size_t n = websocket__envelope__get_packed_size(&env);
  void *buf = malloc(n);
  if (!buf) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    goto err;
  }

  websocket__envelope__pack(&env, buf);
  mg_ws_send(c, buf, n, WEBSOCKET_OP_BINARY);
  free(buf);
  return;
err:
  c->is_closing = 1;
}

void handle_ws_message(struct mg_connection *c, struct mg_ws_message *wm) {
  Websocket__Envelope *env = NULL;

  uint8_t op = wm->flags & 0x0f;
  if (op != WEBSOCKET_OP_BINARY) {
    fprintf(stderr, "[%s:%d] invalid message opcode (flags=0x%02x op=%u)\n",
            __func__, __LINE__, wm->flags, op);
    goto cleanup;
  }

  struct ws_ctx *ctx = c->fn_data;
  if (!ctx) {
    fprintf(stderr, "[%s:%d] context missing\n", __func__, __LINE__);
    goto err;
  }

  env =
      websocket__envelope__unpack(NULL, wm->data.len, (uint8_t *)wm->data.buf);
  if (!env) {
    fprintf(stderr, "[%s:%d] invalid message\n", __func__, __LINE__);
    if (ctx->id == -1) goto err;
    goto cleanup;
  }

  if (ctx->id == -1 &&
      env->payload_case != WEBSOCKET__ENVELOPE__PAYLOAD_CHALLENGE_RESPONSE)
    goto err;

  switch (env->payload_case) {
    case WEBSOCKET__ENVELOPE__PAYLOAD_CHALLENGE_RESPONSE:
      handle_ws_challenge_response(c, env->challenge_response);
      break;
    default:
      break;
  }

  goto cleanup;
err:
  c->is_closing = 1;
cleanup:
  if (env) websocket__envelope__free_unpacked(env, NULL);
}

void handle_ws_challenge_response(struct mg_connection *c,
                                  Websocket__ChallengeResponse *msg) {
  sqlite3_stmt *stmt = NULL;

  if (msg->signature.len != XEDDSA_SIGNATURE_LENGTH) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    goto err;
  }

  int rc;
  if ((rc = sqlite3_prepare_v3(db,
                               "select id,ik from identities where handle = ?;",
                               -1, 0, &stmt, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  if ((rc = sqlite3_bind_text(stmt, 1, msg->handle, -1, SQLITE_STATIC)) !=
      SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  switch (rc = sqlite3_step(stmt)) {
    case SQLITE_ROW:
      break;
    case SQLITE_DONE: {
      fprintf(stderr, "[%s:%d] unknown identity\n", __func__, __LINE__);
      goto err;
    }
    default: {
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      goto err;
    }
  }

  int64_t id = sqlite3_column_int64(stmt, 0);
  const void *pk_buf = sqlite3_column_blob(stmt, 1);
  int pk_len = sqlite3_column_bytes(stmt, 1);

  if (!pk_buf || pk_len != CURVE25519_PUBLIC_KEY_LENGTH) {
    fprintf(stderr, "[%s:%d] invalid public key buffer\n", __func__, __LINE__);
    goto err;
  }

  struct ws_ctx *ctx = c->fn_data;
  if (!xeddsa_verify(pk_buf, ctx->nonce, sizeof ctx->nonce,
                     msg->signature.data)) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    goto err;
  }

  ctx->id = id;

  check_opk_status(c);

  goto cleanup;
err:
  c->is_draining = 1;
cleanup:
  if (stmt) sqlite3_finalize(stmt);
}

struct mg_connection *find_ws_conn_by_id(struct mg_mgr *mgr, int64_t id) {
  for (struct mg_connection *c = mgr->conns; c; c = c->next) {
    if (!c->is_websocket) continue;
    struct ws_ctx *ctx = c->fn_data;
    if (ctx && ctx->id == id) return c;
  }
  return NULL;
}

void check_opk_status(struct mg_connection *c) {
  sqlite3_stmt *stmt0 = NULL, *stmt1 = NULL, *stmt2 = NULL, *stmt3 = NULL;

  struct ws_ctx *ctx = c->fn_data;
  if (!ctx || ctx->id == -1) {
    fprintf(stderr, "[%s:%d] ran on un-initialized connection\n", __func__,
            __LINE__);
    goto err;
  }

  const char *sql0 = "select uid,used from pqopks where `for` = ?;";
  const char *sql1 = "select uid,used from opks where `for` = ?;";
  const char *sql2 = "delete from pqopks where `for` = ? and used = 1;";
  const char *sql3 = "delete from opks where `for` = ? and used = 1;";

  int rc;
  if ((rc = sqlite3_prepare_v3(db, sql0, -1, 0, &stmt0, NULL)) != SQLITE_OK ||
      (rc = sqlite3_prepare_v3(db, sql1, -1, 0, &stmt1, NULL)) != SQLITE_OK ||
      (rc = sqlite3_prepare_v3(db, sql2, -1, 0, &stmt2, NULL)) != SQLITE_OK ||
      (rc = sqlite3_prepare_v3(db, sql3, -1, 0, &stmt3, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  if ((rc = sqlite3_bind_int64(stmt0, 1, ctx->id)) != SQLITE_OK ||
      (rc = sqlite3_bind_int64(stmt1, 1, ctx->id)) != SQLITE_OK ||
      (rc = sqlite3_bind_int64(stmt2, 1, ctx->id)) != SQLITE_OK ||
      (rc = sqlite3_bind_int64(stmt3, 1, ctx->id)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  Websocket__Envelope env = WEBSOCKET__ENVELOPE__INIT;
  Websocket__KeysUsed pb = WEBSOCKET__KEYS_USED__INIT;

  env.payload_case = WEBSOCKET__ENVELOPE__PAYLOAD_KEYS_USED;
  env.keys_used = &pb;

  int64_t ids[512];
  pb.ids = ids;

  while ((rc = sqlite3_step(stmt0)) == SQLITE_ROW) {
    if (sqlite3_column_int(stmt0, 1)) {
      if (pb.n_ids == sizeof ids / sizeof *ids) continue;
      ids[pb.n_ids++] = sqlite3_column_int64(stmt0, 0);
    } else {
      ++pb.pqopks_remaining;
    }
  }

  while ((rc = sqlite3_step(stmt1)) == SQLITE_ROW) {
    if (sqlite3_column_int(stmt1, 1)) {
      if (pb.n_ids == sizeof ids / sizeof *ids) continue;
      ids[pb.n_ids++] = sqlite3_column_int64(stmt1, 0);
    } else {
      ++pb.opks_remaining;
    }
  }

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  if (pb.n_ids > 0 || pb.opks_remaining <= OPK_CNT_WARNING_THRESHOLD ||
      pb.pqopks_remaining <= OPK_CNT_WARNING_THRESHOLD) {
    size_t n = websocket__envelope__get_packed_size(&env);
    void *buf = malloc(n);
    if (!buf) {
      fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
      goto err;
    }

    websocket__envelope__pack(&env, buf);
    mg_ws_send(c, buf, n, WEBSOCKET_OP_BINARY);
    free(buf);
  }

  if (sqlite3_step(stmt2) != SQLITE_DONE ||
      sqlite3_step(stmt3) != SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    goto err;
  }

err:
  if (stmt0) sqlite3_finalize(stmt0);
  if (stmt1) sqlite3_finalize(stmt1);
  if (stmt2) sqlite3_finalize(stmt2);
  if (stmt3) sqlite3_finalize(stmt3);
}
