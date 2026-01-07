#include "db.h"

#include <stddef.h>
#include <stdio.h>

// clang-format off
static const char *s_sql =
  "create table if not exists identities("
    "id integer primary key autoincrement,"
    "handle text not null unique,"
    "ik blob not null," // identity key
    "spk blob not null," // signed prekey
    "spk_id integer not null,"
    "spk_sig blob not null,"
    "pqspk blob not null," // last-resort post-quantum signed prekey
    "pqspk_id integer not null,"
    "pqspk_sig blob not null"
  ");"
  "create index if not exists idx_identities_handle on identities(handle);"
  "create index if not exists idx_identities_id on identities(id);"

  "create table if not exists pqopks(" // signed one-time pqkem prekeys
    "uid integer primary key autoincrement,"
    "id integer not null,"
    "for integer not null,"
    "bytes blob not null,"
    "sig blob not null, "
    "foreign key (for) references identities(id) on delete cascade"
  ");"
  "create index if not exists idx_pqopks_id on pqopks(id);"

  "create table if not exists opks(" // one-time prekeys
    "uid integer primary key autoincrement,"
    "id integer not null,"
    "for integer not null,"
    "bytes blob not null,"
    "foreign key (for) references identities(id) on delete cascade"
  ");"
  "create index if not exists idx_opks_id on opks(id);"

  "create table if not exists queue("
    "id integer primary key autoincrement,"
    "for integer not null,"
    "msg blob not null,"
    "created_at integer not null default (strftime('%s','now')),"
    "foreign key (for) references identities(id) on delete cascade"
  ");";
// clang-format on

sqlite3 *db = NULL;

int db_init(sqlite3 **out, const char *path) {
  int rc;
  sqlite3 *db;

  if ((rc = sqlite3_open_v2(
           path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) !=
      SQLITE_OK) {
    fprintf(stderr, "[%s] open failed: %d (%s)\n", __func__, rc,
            sqlite3_errmsg(db));
    return rc;
  }

  if ((rc = sqlite3_exec(db, s_sql, NULL, NULL, NULL)) != SQLITE_OK) {
    fprintf(stderr, "[%s] init failed: %d (%s)\n", __func__, rc,
            sqlite3_errmsg(db));
    return rc;
  }

  *out = db;

  return rc;
}

void db_close(sqlite3 *db) {
  if (db) sqlite3_close_v2(db);
}
