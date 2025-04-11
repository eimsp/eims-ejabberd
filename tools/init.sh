#!/bin/bash
set -e
export PGPASSWORD=$POSTGRES_PASSWORD;
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  CREATE USER $APP_DB_USER WITH PASSWORD '$APP_DB_PASS';
  GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO $APP_DB_USER;
  alter database $POSTGRES_DB owner to $APP_DB_USER;
  \connect $POSTGRES_DB $APP_DB_USER
  COMMIT;
EOSQL
#psql $POSTGRES_DB < /docker-entrypoint-initdb.d/pg.sql


