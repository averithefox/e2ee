#include "handlers/websocket.h"

#include <openssl/rand.h>
#include <sqlite3.h>

#include "db.h"
#include "mongoose.h"
#include "util.h"
#include "websocket.pb-c.h"

void handle_ws_upgrade_request(struct mg_connection *c,
                               struct mg_http_message *hm) {
  mg_ws_upgrade(c, hm, NULL);
}

void handle_ws_open(struct mg_connection *c, struct mg_http_message *hm) {
  (void)hm;

  uint8_t challenge_bytes[32];
  if (RAND_bytes(challenge_bytes, sizeof challenge_bytes) != 1) {
    c->is_closing = 1;
    return;
  }

  Websocket__Challenge ch = WEBSOCKET__CHALLENGE__INIT;
  ch.challenge.data = challenge_bytes;
  ch.challenge.len = sizeof challenge_bytes;

  Websocket__Envelope env = WEBSOCKET__ENVELOPE__INIT;
  env.payload_case = WEBSOCKET__ENVELOPE__PAYLOAD_CHALLENGE;
  env.challenge = &ch;

  size_t n = websocket__envelope__get_packed_size(&env);
  void *buf = malloc(n);
  if (!buf) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    c->is_closing = 1;
    return;
  }

  websocket__envelope__pack(&env, buf);
  mg_ws_send(c, buf, n, WEBSOCKET_OP_BINARY);
  memcpy(c->data, challenge_bytes, sizeof c->data);
  free(buf);
}

void handle_ws_message(struct mg_connection *c, struct mg_ws_message *wm) {
  if (wm->flags & ~WEBSOCKET_OP_BINARY) {
    fprintf(stderr, "[%s:%d] invalid message flags\n", __func__, __LINE__);
    return;
  }

  Websocket__Envelope *env =
      websocket__envelope__unpack(NULL, wm->data.len, (uint8_t *)wm->data.buf);
  if (!env) {
    fprintf(stderr, "[%s:%d] invalid message\n", __func__, __LINE__);
    return;
  }

  switch (env->payload_case) {
    case WEBSOCKET__ENVELOPE__PAYLOAD_CHALLENGE_RESPONSE:
      handle_ws_challenge_response(c, env->challenge_response);
      break;
    default:
      break;
  }

  websocket__envelope__free_unpacked(env, NULL);
}

void handle_ws_challenge_response(struct mg_connection *c,
                                  Websocket__ChallengeResponse *msg) {
  sqlite3_stmt *stmt = NULL;
  EVP_PKEY *pkey = NULL;

  if (sqlite3_prepare_v3(db,
                         "select signing_key from identities where handle = ?;",
                         -1, 0, &stmt, NULL) < 0) {
    fprintf(stderr, "[%s:%d] prepare failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    goto err;
  }

  if (sqlite3_bind_text(stmt, 1, msg->handle, -1, SQLITE_STATIC) < 0) {
    fprintf(stderr, "[%s:%d] bind failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    goto err;
  }

  int err = sqlite3_step(stmt);
  if (err == SQLITE_DONE) {
    fprintf(stderr, "[%s:%d] unknown identity\n", __func__, __LINE__);
    goto err;
  }

  if (err != SQLITE_ROW) {
    fprintf(stderr, "[%s:%d] step failed: %s\n", __func__, __LINE__,
            sqlite3_errmsg(db));
    goto err;
  }

  const void *buf = sqlite3_column_blob(stmt, 0);
  int len = sqlite3_column_bytes(stmt, 0);

  if (!buf || len <= 0) {
    fprintf(stderr, "[%s:%d] invalid public key buffer\n", __func__, __LINE__);
    goto err;
  }

  if ((pkey = load_pub_enc_key_from_spki(buf, len)) == NULL) goto err;

  if (verify_signature((uint8_t *)c->data, sizeof c->data, msg->signature.data,
                       msg->signature.len, pkey) != 1) {
    fprintf(stderr, "[%s:%d] invalid signature\n", __func__, __LINE__);
    goto err;
  }

  goto cleanup;
err:
  c->is_draining = 1;
cleanup:
  if (stmt) sqlite3_finalize(stmt);
  if (pkey) EVP_PKEY_free(pkey);
}
