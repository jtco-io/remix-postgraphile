import { createPostGraphileSchema } from "postgraphile";
import pgPool from "~/utils/pgPool.server";
import PassportLoginPlugin from "~/schema/plugins/PassportLoginPlugin";

const schema = createPostGraphileSchema(pgPool, "app_public", {
  appendPlugins: [PassportLoginPlugin],
});

export default schema;
