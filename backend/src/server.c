#include "server.h"

#include <mongoose.h>

#include "handlers/identity.h"
#include "handlers/prekey_bundle.h"
#include "handlers/websocket.h"

void handle_server_event(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_WS_OPEN) {
    handle_ws_open(c, ev_data);
  } else if (ev == MG_EV_WS_MSG) {
    handle_ws_message(c, ev_data);
  } else if (ev == MG_EV_CLOSE) {
    if (c->fn_data) free(c->fn_data);
  }

  if (ev != MG_EV_HTTP_MSG) return;
  struct mg_http_message *hm = ev_data;

  printf("%.*s %.*s%c%.*s\n", (int)hm->method.len, hm->method.buf,
         (int)hm->uri.len, hm->uri.buf, hm->query.len ? '?' : 0,
         (int)hm->query.len, hm->query.buf);

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

  if (mg_match(hm->uri, mg_str("/api/#"), NULL)) {
    struct mg_str caps[2];
    if (mg_strcmp(hm->uri, mg_str("/api/identity")) == 0) {
      handle_identity_request(c, hm);
    } else if (mg_strcmp(hm->uri, mg_str("/api/ws")) == 0) {
      handle_ws_upgrade_request(c, hm);
    } else if (mg_match(hm->uri, mg_str("/api/keys/*/bundle"), caps)) {
      handle_prekey_bundle_request(c, hm, &caps[0]);
    } else {
      mg_http_reply(c, 404, "", "");
    }
  } else {
    struct mg_http_serve_opts opts = {
        .root_dir = "./public",
        .page404 = "./public/index.html",
    };
    mg_http_serve_dir(c, hm, &opts);
  }
}
