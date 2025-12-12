#pragma once

#include <mongoose.h>

#include "websocket.pb-c.h"

struct ws_ctx {
  uint8_t chlg[32];  // challenge bytes
};

void handle_ws_upgrade_request(struct mg_connection *c,
                               struct mg_http_message *hm);
void handle_ws_open(struct mg_connection *c, struct mg_http_message *hm);
void handle_ws_message(struct mg_connection *c, struct mg_ws_message *wm);
void handle_ws_challenge_response(struct mg_connection *c,
                                  Websocket__ChallengeResponse *msg);
