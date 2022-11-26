const dotenv = require("dotenv");
// dotenv must be called before config loads
dotenv.config({ path: "../.env" });

const { DATABASE_ROOT_URI, DATABASE_OWNER_URI, DATABASE_NAME } = process.env;

module.exports = {
  rootConnectionString: DATABASE_ROOT_URI,
  connectionString: DATABASE_OWNER_URI,
  shadowConnectionString: `${DATABASE_OWNER_URI}_shadow`,
  placeholders: {
    ":DATABASE_AUTHENTICATOR": `${DATABASE_NAME}_authenticator`,
    ":DATABASE_VISITOR": `${DATABASE_NAME}_authenticator`,
  },
  afterAllMigrations: [
    {
      _: "command",
      command:
        'if [ -z "$CI" ]; then pg_dump --schema-only --no-owner --exclude-schema=graphile_migrate --file=database-schema.sql $GM_DBURL; fi',
    },
  ],
  afterCurrent: [],
};
