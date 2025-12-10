#pragma once

#include <mongoose.h>

void handle_server_event(struct mg_connection *c, int ev, void *ev_data);
