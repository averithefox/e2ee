#pragma once

#include <mongoose.h>

void handle_new_identity_request(struct mg_connection *c,
                                 struct mg_http_message *hm);
