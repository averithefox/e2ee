#include "server.h"

#include <mongoose.h>

#include "handlers/new_identity.h"

void handle_server_event(struct mg_connection *c, int ev, void *ev_data) {
  if (ev != MG_EV_HTTP_MSG) return;

  struct mg_http_message *hm = ev_data;

  printf("%.*s %.*s\n", (int)hm->method.len, hm->method.buf, (int)hm->uri.len,
         hm->uri.buf);

  if (mg_strcmp(hm->uri, mg_str("/api/new-identity")) == 0) {
    handle_new_identity_request(c, hm);
  } else {
    mg_http_reply(c, 404, "", "");
  }
}
