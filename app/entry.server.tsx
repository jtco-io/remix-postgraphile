import { PassThrough } from "stream";
import type { EntryContext } from "@remix-run/node";
import { Response } from "@remix-run/node";
import { RemixServer } from "@remix-run/react";
import isbot from "isbot";
import { renderToPipeableStream } from "react-dom/server";
import { ApolloClient, ApolloProvider, InMemoryCache } from "@apollo/client";
import { getDataFromTree } from "@apollo/client/react/ssr";
import { GraphileApolloLink } from "~/utils/graphileApolloLink.server";

const ABORT_DELAY = 5000;

export default function handleRequest(
  request: Request,
  responseStatusCode: number,
  responseHeaders: Headers,
  remixContext: EntryContext
) {
  return handleBrowserRequest(
    request,
    responseStatusCode,
    responseHeaders,
    remixContext
  );
  // return isbot(request.headers.get("user-agent"))
  //   ? handleBotRequest(
  //       request,
  //       responseStatusCode,
  //       responseHeaders,
  //       remixContext
  //     )
  //   : handleBrowserRequest(
  //       request,
  //       responseStatusCode,
  //       responseHeaders,
  //       remixContext
  //     );
}

function handleBotRequest(
  request: Request,
  responseStatusCode: number,
  responseHeaders: Headers,
  remixContext: EntryContext
) {
  return new Promise((resolve, reject) => {
    let didError = false;

    const { pipe, abort } = renderToPipeableStream(
      <RemixServer context={remixContext} url={request.url} />,
      {
        onAllReady() {
          const body = new PassThrough();

          responseHeaders.set("Content-Type", "text/html");

          resolve(
            new Response(body, {
              headers: responseHeaders,
              status: didError ? 500 : responseStatusCode,
            })
          );

          pipe(body);
        },
        onShellError(error: unknown) {
          reject(error);
        },
        onError(error: unknown) {
          didError = true;

          console.error(error);
        },
      }
    );

    setTimeout(abort, ABORT_DELAY);
  });
}

async function handleBrowserRequest(
  request: Request,
  responseStatusCode: number,
  responseHeaders: Headers,
  remixContext: EntryContext
) {
  return new Promise((resolve, reject) => {
    let didError = false;

    const graphqlClient = new ApolloClient({
      cache: new InMemoryCache(),
      ssrMode: true,
      link: new GraphileApolloLink(),
    });
    const App = (
      <ApolloProvider client={graphqlClient}>
        <RemixServer context={remixContext} url={request.url} />
      </ApolloProvider>
    );
    return getDataFromTree(App).then(() => {
      const initialState = graphqlClient.extract();
      const { pipe, abort } = renderToPipeableStream(
        <>
          {App}
          <script
            dangerouslySetInnerHTML={{
              __html: `window.__APOLLO_STATE__=${JSON.stringify(
                initialState
              ).replace(/</g, "\\u003c")}`, // The replace call escapes the < character to prevent cross-site scripting attacks that are possible via the presence of </script> in a string literal
            }}
          />
        </>,
        {
          onShellReady() {
            const body = new PassThrough();

            responseHeaders.set("Content-Type", "text/html");

            resolve(
              new Response(body, {
                headers: responseHeaders,
                status: didError ? 500 : responseStatusCode,
              })
            );

            pipe(body);
          },
          onShellError(err: unknown) {
            reject(err);
          },
          onError(error: unknown) {
            didError = true;

            console.error(error);
          },
        }
      );

      setTimeout(abort, ABORT_DELAY);
    });
  });
}
