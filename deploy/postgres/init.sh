#!/bin/sh
# Runs once on first start of the Postgres volume. Creates the runtime roles
# (the domain migration creates them too, but without passwords) and a separate
# database for the web app's auth tables.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE depguard_app LOGIN PASSWORD '${DEPGUARD_APP_PASSWORD}';
CREATE ROLE depguard_query LOGIN PASSWORD '${DEPGUARD_QUERY_PASSWORD}';
CREATE ROLE depguard_web LOGIN PASSWORD '${DEPGUARD_WEB_PASSWORD}';
CREATE DATABASE depguard_web OWNER depguard_web;
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO depguard_app, depguard_query;
GRANT USAGE ON SCHEMA public TO depguard_app, depguard_query;
ALTER ROLE depguard_query SET statement_timeout = '10s';
SQL
