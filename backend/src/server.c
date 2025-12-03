#include "server.h"

void
handle_server_event (struct mg_connection *c, int ev, void *ev_data)
{
  if (ev != MG_EV_HTTP_MSG)
    return;

  struct mg_http_message *hm = ev_data;

  printf ("%.*s %.*s\n", (int)hm->method.len, hm->method.buf, (int)hm->uri.len,
          hm->uri.buf);

  mg_http_reply (c, 404, "", "");
}
