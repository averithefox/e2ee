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
      handle_ws_challenge_response_pb(c, env->challenge_response);
      break;
    case WEBSOCKET__ENVELOPE__PAYLOAD_FORWARD:
      handle_ws_forward_pb(c, env->forward);
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

void handle_ws_challenge_response_pb(struct mg_connection *c,
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

  handle_ws_authenticated(c);

  goto cleanup;
err:
  c->is_draining = 1;
cleanup:
  if (stmt) sqlite3_finalize(stmt);
}

void handle_ws_authenticated(struct mg_connection *c) {
  sqlite3_stmt *stmt_select = NULL, *stmt_delete = NULL;

  struct ws_ctx *ctx = c->fn_data;
  if (!ctx || ctx->id == -1) {
    fprintf(stderr, "[%s:%d] context invalid or missing\n", __func__, __LINE__);
    c->is_draining = 1;
    goto err;
  }

  int rc;
  if ((rc = sqlite3_prepare_v3(
           db,
           "select id,msg from queue where for = ? order by created_at asc;",
           -1, 0, &stmt_select, NULL)) != SQLITE_OK ||
      (rc = sqlite3_prepare_v3(db, "delete from queue where id = ?;", -1, 0,
                               &stmt_delete, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  if ((rc = sqlite3_bind_int64(stmt_select, 1, ctx->id)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  while ((rc = sqlite3_step(stmt_select)) == SQLITE_ROW) {
    int64_t id = sqlite3_column_int64(stmt_select, 0);
    const void *msg_buf = sqlite3_column_blob(stmt_select, 1);
    int msg_len = sqlite3_column_bytes(stmt_select, 1);

    ws_send_by_id(c->mgr, ctx->id, msg_buf, msg_len);

    if ((rc = sqlite3_bind_int64(stmt_delete, 1, id)) != SQLITE_OK) {
      fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      continue;
    }
    if ((rc = sqlite3_step(stmt_delete)) != SQLITE_DONE) {
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      continue;
    }
    sqlite3_reset(stmt_delete);
    sqlite3_clear_bindings(stmt_delete);
  }

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

err:
  if (stmt_select) sqlite3_finalize(stmt_select);
  if (stmt_delete) sqlite3_finalize(stmt_delete);
}

void handle_ws_forward_pb(struct mg_connection *c, Websocket__Forward *msg) {
  sqlite3_stmt *stmt_id_by_handle = NULL, *stmt_handle_by_id = NULL;

  struct ws_ctx *ctx = c->fn_data;
  if (!ctx || ctx->id == -1) {
    fprintf(stderr, "[%s:%d] context invalid or missing\n", __func__, __LINE__);
    c->is_draining = 1;
    goto err;
  }

  int rc;
  if ((rc =
           sqlite3_prepare_v3(db, "select id from identities where handle = ?;",
                              -1, 0, &stmt_id_by_handle, NULL)) != SQLITE_OK ||
      (rc =
           sqlite3_prepare_v3(db, "select handle from identities where id = ?;",
                              -1, 0, &stmt_handle_by_id, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  if ((rc = sqlite3_bind_text(stmt_id_by_handle, 1, msg->handle, -1,
                              SQLITE_STATIC)) != SQLITE_OK ||
      (rc = sqlite3_bind_int64(stmt_handle_by_id, 1, ctx->id)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  switch (rc = sqlite3_step(stmt_id_by_handle)) {
    case SQLITE_ROW:
      break;
    case SQLITE_DONE:
      fprintf(stderr, "[%s:%d] unknown identity\n", __func__, __LINE__);
      goto err;
    default:
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      goto err;
  }

  switch (rc = sqlite3_step(stmt_handle_by_id)) {
    case SQLITE_ROW:
      break;
    case SQLITE_DONE:
      fprintf(stderr, "[%s:%d] unknown identity\n", __func__, __LINE__);
      goto err;
    default:
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      goto err;
  }

  int64_t id = sqlite3_column_int64(stmt_id_by_handle, 0);
  char *handle = (char *)sqlite3_column_text(stmt_handle_by_id, 0);

  Websocket__Forward forward = WEBSOCKET__FORWARD__INIT;
  forward.handle = handle;
  forward.payload_case = msg->payload_case;
  forward.pqxdh_init = msg->pqxdh_init;

  size_t n = websocket__forward__get_packed_size(&forward);
  void *buf = malloc(n);
  if (!buf) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    goto err;
  }
  websocket__forward__pack(&forward, buf);
  ws_send_by_id(c->mgr, id, buf, n);
  free(buf);

err:
  if (stmt_id_by_handle) sqlite3_finalize(stmt_id_by_handle);
  if (stmt_handle_by_id) sqlite3_finalize(stmt_handle_by_id);
}

struct mg_connection *find_ws_conn_by_id(struct mg_mgr *mgr, int64_t id) {
  for (struct mg_connection *c = mgr->conns; c; c = c->next) {
    if (!c->is_websocket) continue;
    struct ws_ctx *ctx = c->fn_data;
    if (ctx && ctx->id == id) return c;
  }
  return NULL;
}

void ws_send_by_id(struct mg_mgr *mgr, int64_t id, const void *buf,
                   size_t len) {
  sqlite3_stmt *stmt = NULL;

  struct mg_connection *c = find_ws_conn_by_id(mgr, id);
  if (c) {
    mg_ws_send(c, buf, len, WEBSOCKET_OP_BINARY);
    return;
  }

  int rc;
  if ((rc = sqlite3_prepare_v3(db, "insert into queue (for,msg) values (?,?);",
                               -1, 0, &stmt, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  if ((rc = sqlite3_bind_int64(stmt, 1, id)) != SQLITE_OK ||
      (rc = sqlite3_bind_blob(stmt, 2, buf, len, SQLITE_STATIC)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

  if ((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    goto err;
  }

err:
  if (stmt) sqlite3_finalize(stmt);
}
