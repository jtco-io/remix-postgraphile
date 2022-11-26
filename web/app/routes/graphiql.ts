import type { LoaderFunction } from "@remix-run/node";
import graphiqlHTML from "postgraphile/build/assets/graphiql.html";

export const loader: LoaderFunction = () => {
  return new Response(
    graphiqlHTML?.replace("http://localhost:5000/graphql", "/graphql"),
    {
      headers: { "Content-Type": "text/html" },
    }
  );
};
