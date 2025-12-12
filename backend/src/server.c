#include "server.h"

#include <mongoose.h>

#include "handlers/get_identity.h"
#include "handlers/new_identity.h"
#include "handlers/websocket.h"

void handle_server_event(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_WS_OPEN) {
    handle_ws_open(c, ev_data);
  } else if (ev == MG_EV_WS_MSG) {
    handle_ws_message(c, ev_data);
  }

  if (ev != MG_EV_HTTP_MSG) return;
  struct mg_http_message *hm = ev_data;

  printf("%.*s %.*s\n", (int)hm->method.len, hm->method.buf, (int)hm->uri.len,
         hm->uri.buf);

  if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
    mg_http_reply(c, 204,
                  ""
#ifndef NDEBUG
                  "Access-Control-Allow-Origin: *\r\n"
#endif
                  "Access-Control-Allow-Methods: *\r\n"
                  "Access-Control-Allow-Headers: *\r\n",
                  "");
    return;
  }

  if (mg_strcmp(hm->uri, mg_str("/api/new-identity")) == 0) {
    handle_new_identity_request(c, hm);
  } else if (mg_strcmp(hm->uri, mg_str("/api/ws")) == 0) {
    handle_ws_upgrade_request(c, hm);
  } else if (mg_strcmp(hm->uri, mg_str("/api/get-identity")) == 0) {
    handle_get_identity_request(c, hm);
  } else {
    mg_http_reply(c, 404, "", "");
  }
}
