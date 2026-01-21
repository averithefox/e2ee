#include "handlers/websocket.h"

#include <crypto.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include "db.h"
#include "mongoose.h"
#include "websocket.pb-c.h"

#define SELF -1
#define NONE -1

#define ERR(CODE)                                     \
  do {                                                \
    ws_ack(c, msg_id, WEBSOCKET__ACK__ERROR__##CODE); \
    goto err;                                         \
  } while (0)

static bool ws_send(struct mg_connection *c,
                    const Websocket__ClientboundMessage *env, int64_t to_id) {
  size_t n = websocket__clientbound_message__get_packed_size(env);
  void *buf = malloc(n);
  if (!buf) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    return false;
  }
  websocket__clientbound_message__pack(env, buf);
  if (to_id == SELF) {
    mg_ws_send(c, buf, n, WEBSOCKET_OP_BINARY);
  } else {
    ws_send_by_id(c->mgr, to_id, buf, n);
  }
  free(buf);
  return true;
}

static bool ws_ack(struct mg_connection *c, int64_t message_id,
                   Websocket__Ack__Error error) {
  Websocket__Ack ack = WEBSOCKET__ACK__INIT;
  ack.message_id = message_id;
  if ((int)error != -1) {
    ack.has_error = true;
    ack.error = error;
  }

  Websocket__ClientboundMessage env = WEBSOCKET__CLIENTBOUND_MESSAGE__INIT;
  env.payload_case = WEBSOCKET__CLIENTBOUND_MESSAGE__PAYLOAD_ACK;
  env.ack = &ack;

  return ws_send(c, &env, SELF);
}

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

  Websocket__ClientboundMessage env = WEBSOCKET__CLIENTBOUND_MESSAGE__INIT;
  env.payload_case = WEBSOCKET__CLIENTBOUND_MESSAGE__PAYLOAD_CHALLENGE;
  env.challenge = &ch;

  if (!ws_send(c, &env, SELF)) goto err;
  return;
err:
  c->is_closing = 1;
}

void handle_ws_message(struct mg_connection *c, struct mg_ws_message *wm) {
  Websocket__ServerboundMessage *env = NULL;

  struct ws_ctx *ctx = c->fn_data;
  if (!ctx) {
    fprintf(stderr, "[%s:%d] context missing\n", __func__, __LINE__);
    goto err;
  }

  uint8_t op = wm->flags & 0x0f;
  if (op != WEBSOCKET_OP_BINARY) {
    fprintf(stderr, "[%s:%d] invalid message opcode (flags=0x%02x op=%u)\n",
            __func__, __LINE__, wm->flags, op);
    goto cleanup;
  }

  env = websocket__serverbound_message__unpack(NULL, wm->data.len,
                                               (uint8_t *)wm->data.buf);
  if (!env) {
    fprintf(stderr, "[%s:%d] invalid message\n", __func__, __LINE__);
    if (ctx->id == -1) goto err;
    goto cleanup;
  }

  if (ctx->id == -1 &&
      env->payload_case !=
          WEBSOCKET__SERVERBOUND_MESSAGE__PAYLOAD_CHALLENGE_RESPONSE) {
    if (!ws_ack(c, env->id, WEBSOCKET__ACK__ERROR__UNAUTHENTICATED)) goto err;
    goto cleanup;
  }

  switch (env->payload_case) {
    case WEBSOCKET__SERVERBOUND_MESSAGE__PAYLOAD_CHALLENGE_RESPONSE:
      handle_ws_challenge_response_pb(c, env->challenge_response, env->id);
      break;
    case WEBSOCKET__SERVERBOUND_MESSAGE__PAYLOAD_FORWARD:
      handle_ws_forward_pb(c, env->forward, env->id);
      break;
    default:
      break;
  }

  goto cleanup;
err:
  c->is_draining = 1;
cleanup:
  if (env) websocket__serverbound_message__free_unpacked(env, NULL);
}

void handle_ws_challenge_response_pb(struct mg_connection *c,
                                     Websocket__ChallengeResponse *msg,
                                     int64_t msg_id) {
  sqlite3_stmt *stmt = NULL;

  struct ws_ctx *ctx = c->fn_data;
  if (!ctx) {
    fprintf(stderr, "[%s:%d] context missing\n", __func__, __LINE__);
    goto err;
  }

  if (msg->signature.len != XEDDSA_SIGNATURE_LENGTH) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    ERR(INVALID_SIGNATURE);
  }

  int rc;
  if ((rc = sqlite3_prepare_v3(db,
                               "select id,ik from identities where handle = ?;",
                               -1, 0, &stmt, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] prepare failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(SERVER_ERROR);
  }

  if ((rc = sqlite3_bind_text(stmt, 1, msg->handle, -1, SQLITE_STATIC)) !=
      SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(SERVER_ERROR);
  }

  switch (rc = sqlite3_step(stmt)) {
    case SQLITE_ROW:
      break;
    case SQLITE_DONE: {
      fprintf(stderr, "[%s:%d] unknown identity\n", __func__, __LINE__);
      ERR(UNKNOWN_IDENTITY);
    }
    default: {
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      ERR(SERVER_ERROR);
    }
  }

  int64_t id = sqlite3_column_int64(stmt, 0);
  const void *pk_buf = sqlite3_column_blob(stmt, 1);
  int pk_len = sqlite3_column_bytes(stmt, 1);

  if (!pk_buf || pk_len != CURVE25519_PUBLIC_KEY_LENGTH) {
    fprintf(stderr, "[%s:%d] invalid public key buffer\n", __func__, __LINE__);
    ERR(SERVER_ERROR);
  }

  if (!xeddsa_verify(pk_buf, ctx->nonce, sizeof ctx->nonce,
                     msg->signature.data)) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    ERR(INVALID_SIGNATURE);
  }

  ctx->id = id;

  ws_ack(c, msg_id, NONE);
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
    goto err;
  }

  // clang-format off
  const char *sql_select = "select id,msg from queue where for=? order by created_at asc;";
  const char *sql_delete = "delete from queue where id=?;";
  // clang-format on

  int rc;
  if ((rc = sqlite3_prepare_v3(db, sql_select, -1, 0, &stmt_select, NULL)) !=
          SQLITE_OK ||
      (rc = sqlite3_prepare_v3(db, sql_delete, -1, 0, &stmt_delete, NULL)) !=
          SQLITE_OK) {
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

void handle_ws_forward_pb(struct mg_connection *c, Websocket__Forward *msg,
                          int64_t msg_id) {
  sqlite3_stmt *stmt_id_by_handle = NULL, *stmt_handle_by_id = NULL;

  struct ws_ctx *ctx = c->fn_data;
  if (!ctx || ctx->id == -1) {
    fprintf(stderr, "[%s:%d] context invalid or missing\n", __func__, __LINE__);
    ERR(SERVER_ERROR);
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
    ERR(SERVER_ERROR);
  }

  if ((rc = sqlite3_bind_text(stmt_id_by_handle, 1, msg->handle, -1,
                              SQLITE_STATIC)) != SQLITE_OK ||
      (rc = sqlite3_bind_int64(stmt_handle_by_id, 1, ctx->id)) != SQLITE_OK) {
    fprintf(stderr, "[%s:%d] bind failed: %d (%s)\n", __func__, __LINE__, rc,
            sqlite3_errmsg(db));
    ERR(SERVER_ERROR);
  }

  switch (rc = sqlite3_step(stmt_id_by_handle)) {
    case SQLITE_ROW:
      break;
    case SQLITE_DONE:
      fprintf(stderr, "[%s:%d] unknown identity\n", __func__, __LINE__);
      ERR(UNKNOWN_IDENTITY);
    default:
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      ERR(SERVER_ERROR);
  }

  switch (rc = sqlite3_step(stmt_handle_by_id)) {
    case SQLITE_ROW:
      break;
    case SQLITE_DONE:
      fprintf(stderr, "[%s:%d] unknown identity\n", __func__, __LINE__);
      ERR(UNKNOWN_IDENTITY);
    default:
      fprintf(stderr, "[%s:%d] step failed: %d (%s)\n", __func__, __LINE__, rc,
              sqlite3_errmsg(db));
      ERR(SERVER_ERROR);
  }

  int64_t id = sqlite3_column_int64(stmt_id_by_handle, 0);
  char *handle = (char *)sqlite3_column_text(stmt_handle_by_id, 0);

  Websocket__Forward forward = WEBSOCKET__FORWARD__INIT;
  forward.handle = handle;
  forward.payload_case = msg->payload_case;
  switch (forward.payload_case) {
    case WEBSOCKET__FORWARD__PAYLOAD_PQXDH_INIT:
      forward.pqxdh_init = msg->pqxdh_init;
      break;
    case WEBSOCKET__FORWARD__PAYLOAD_MESSAGE:
      forward.message = msg->message;
      break;
    case WEBSOCKET__FORWARD__PAYLOAD__NOT_SET:
    case _WEBSOCKET__FORWARD__PAYLOAD__CASE_IS_INT_SIZE:
      ERR(INVALID_MESSAGE);
  }

  Websocket__ClientboundMessage env = WEBSOCKET__CLIENTBOUND_MESSAGE__INIT;
  env.payload_case = WEBSOCKET__CLIENTBOUND_MESSAGE__PAYLOAD_FORWARD;
  env.forward = &forward;

  ws_ack(c, msg_id, NONE);
  ws_send(c, &env, id);
err:
  if (stmt_id_by_handle) sqlite3_finalize(stmt_id_by_handle);
  if (stmt_handle_by_id) sqlite3_finalize(stmt_handle_by_id);
}

static struct mg_connection *find_ws_conn_by_id(struct mg_mgr *mgr,
                                                int64_t id) {
  for (struct mg_connection *c = mgr->conns; c; c = c->next) {
    if (!c->is_websocket) continue;
    struct ws_ctx *ctx = c->fn_data;
    if (ctx && ctx->id == id) return c;
  }
  return NULL;
}

bool ws_send_by_id(struct mg_mgr *mgr, int64_t id, const void *buf,
                   size_t len) {
  sqlite3_stmt *stmt = NULL;

  struct mg_connection *c = find_ws_conn_by_id(mgr, id);
  if (c) {
    mg_ws_send(c, buf, len, WEBSOCKET_OP_BINARY);
    return true;
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

  return true;
err:
  if (stmt) sqlite3_finalize(stmt);
  return false;
}
