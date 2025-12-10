#include <mongoose.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>

#include "db.h"
#include "server.h"

static const char *s_listening_addr = "http://0.0.0.0:8000";

static int s_signo;
inline static void signal_handler(int signo) { s_signo = signo; }

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    char *arg = argv[i];
    if (strcmp(arg, "--listen") == 0 || strcmp(arg, "-l") == 0) {
      s_listening_addr = argv[++i];
    } else if (strcmp(arg, "--help") == 0) {
      fprintf(stdout,
              "Usage: %s [OPTIONS]\n"
              "\n"
              "Options:\n"
              "  -l, --listen ADDR    Set listening address (default: "
              "http://0.0.0.0:8000)\n"
              "  --help               Show this help message and exit\n",
              argv[0]);
      return EXIT_SUCCESS;
    } else {
      fprintf(stderr,
              "illegal option: %s\ntry `%s --help` for more "
              "information.\n",
              arg, argv[0]);
      return EXIT_FAILURE;
    }
  }

  struct mg_mgr mgr;
  struct mg_connection *conn;

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  mg_mgr_init(&mgr);
  if ((conn = mg_http_listen(&mgr, s_listening_addr, handle_server_event,
                             NULL)) == NULL) {
    fprintf(stderr,
            "Cannot listen on %s. Use http://ADDR:PORT or "
            ":PORT",
            s_listening_addr);
    return EXIT_FAILURE;
  }

  if (db_init(&db, "data.sqlite") < 0) {
    mg_mgr_free(&mgr);
    return EXIT_FAILURE;
  }

  while (s_signo == 0) {
    mg_mgr_poll(&mgr, 100);
  }

  mg_mgr_free(&mgr);
  db_close(db);

  return EXIT_SUCCESS;
}
