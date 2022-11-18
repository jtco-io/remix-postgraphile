import { createPostGraphileSchema } from "postgraphile";

async function initializeSchema() {
  return createPostGraphileSchema(
    process.env.DATABASE_URL ||
      `postgres://cfpgql_owner:password@localhost:5432/cfpgql`,
    "public"
  );
}
