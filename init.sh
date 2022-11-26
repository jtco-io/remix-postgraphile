# exit when any command fails
set -e

# Parse dotenv
if [ -f .env ]
then
  export $(cat .env | sed 's/#.*//g' | xargs)
fi

# Add some color
NOCOLOR='\033[0m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
LIGHTGREEN='\033[1;32m'

export PGDATABASE=postgres
export PGHOST=${PGHOST:-localhost}
export PGUSER=${DATABASE_ROOT_USER}
export PGPASSWORD=${DATABASE_ROOT_PASSWORD}

DATABASE_OWNER=${DATABASE_NAME}_owner
DATABASE_AUTHENTICATOR=${DATABASE_NAME}_authenticator
DATABASE_VISITOR=${DATABASE_NAME}_visitor
DATABASE_SHADOW_NAME=${DATABASE_NAME}_shadow

yarn install --frozen-lockfile --prefer-offline

# Clean all build files
#node_modules/.bin/tsc --build --clean
#
# Needed for migrations
#node_modules/.bin/graphql-codegen
#node_modules/.bin/tsc --build packages/config dataloader apps/backend apps/worker

drop_database_and_roles () {
  echo "${LIGHTGREEN}Clearing old accounts and database${NOCOLOR}"
  psql -c "DROP DATABASE IF EXISTS ${DATABASE_NAME};"
  psql -c "DROP DATABASE IF EXISTS ${DATABASE_SHADOW_NAME};"
  psql -c "
    DROP ROLE IF EXISTS ${DATABASE_OWNER};
    DROP ROLE IF EXISTS ${DATABASE_AUTHENTICATOR};
    DROP ROLE IF EXISTS ${DATABASE_VISITOR};
  "
}
create_database_and_roles (){
  echo "${LIGHTGREEN}Initializing roles and database${NOCOLOR}"
  psql -c "
    CREATE USER ${DATABASE_OWNER} WITH PASSWORD '${DATABASE_OWNER_PASSWORD}' SUPERUSER;
    CREATE USER ${DATABASE_AUTHENTICATOR} WITH PASSWORD '${DATABASE_AUTHENTICATOR_PASSWORD}' NOINHERIT;
    CREATE USER ${DATABASE_VISITOR};
  "
  psql -c "CREATE DATABASE ${DATABASE_NAME} OWNER ${DATABASE_OWNER};"
  psql -c "CREATE DATABASE ${DATABASE_SHADOW_NAME} OWNER ${DATABASE_OWNER};"
}

drop_database_and_roles
create_database_and_roles
#
#node_modules/.bin/graphile-migrate reset --erase
#node_modules/.bin/graphile-migrate migrate --forceActions
#node dataloader/dist
#sh bin/stagedata.sh




