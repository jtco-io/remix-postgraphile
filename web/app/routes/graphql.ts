import type { ActionFunction } from "@remix-run/node";
import { withPostGraphileContext } from "postgraphile";
import pgPool from "~/utils/pgPool.server";
import { graphql } from "graphql";
import { json } from "@remix-run/node";
import schema from "~/schema";

export const action: ActionFunction = async ({ request }) => {
  const body = await request.json();
  const res = await withPostGraphileContext(
    {
      pgPool,
    },
    async (context) => {
      // Execute your GraphQL query in this function with the provided
      // `context` object, which should NOT be used outside of this
      // function.
      return await graphql(
        await schema, // The schema from `createPostGraphileSchema`
        body.query,
        null,
        { ...context }, // You can add more to context if you like
        body.variables,
        body.operationName
      );
    }
  );
  return json(res);
};
