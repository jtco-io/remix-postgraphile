import {
  ApolloLink,
  FetchResult,
  NextLink,
  Observable,
  Operation,
} from "@apollo/client";
import { getOperationAST, graphql } from "graphql";
import {
  createPostGraphileSchema,
  withPostGraphileContext,
} from "postgraphile";
import pgPool from "~/utils/pgPool.server";

/**
 * A Graphile Apollo link for use during SSR. Allows Apollo Client to resolve
 * server-side requests without requiring an HTTP roundtrip.
 */
export class GraphileApolloLink extends ApolloLink {
  constructor() {
    super();
  }

  request(
    operation: Operation,
    _forward?: NextLink
  ): Observable<FetchResult> | null {
    const source = operation.query.loc?.source.body;
    if (!source) throw new Error("Could not convert graphql query to string");
    console.log("requests!", operation.query.loc?.source.body);
    return new Observable((observer) => {
      (async () => {
        const schema = await createPostGraphileSchema(pgPool, "public");
        const res = await withPostGraphileContext(
          {
            pgPool,
            // pgDefaultRole: "...",
          },
          async (context) => {
            // Execute your GraphQL query in this function with the provided
            // `context` object, which should NOT be used outside of this
            // function.
            return await graphql(
              schema, // The schema from `createPostGraphileSchema`
              source,
              null,
              { ...context }, // You can add more to context if you like
              operation.variables,
              operation.operationName
            );
          }
        );
        try {
          const op = getOperationAST(operation.query, operation.operationName);
          if (!op || op.operation !== "query") {
            if (!observer.closed) {
              /* Only do queries (not subscriptions) on server side */
              observer.complete();
            }
            return;
          }
          if (!observer.closed) {
            // observer.next(data);
            observer.next(res);
            observer.complete();
          }
        } catch (e) {
          if (!observer.closed) {
            observer.error(e);
          } else {
            console.error(e);
          }
        }
      })();
    });
  }
}
