#include "server.h"
#include <mongoose.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>

static int s_signo;
inline static void
signal_handler (int signo)
{
  s_signo = signo;
}

int
main (void)
{
  struct mg_mgr mgr;
  struct mg_connection *conn;

  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);

  mg_mgr_init (&mgr);
  if ((conn = mg_http_listen (&mgr, "http://localhost:3000",
                              handle_server_event, NULL))
      == NULL)
    {
      return EXIT_FAILURE;
    }

  while (s_signo == 0)
    {
      mg_mgr_poll (&mgr, 100);
    }

  mg_mgr_free (&mgr);

  return EXIT_SUCCESS;
}
