import React from "react";
import { LoginMutationVariables, useLoginMutation } from "./Login.generated";
import { ViewerDocument, ViewerQuery } from "~/utils/useViewerQuery.generated";

import { useNavigate } from "@remix-run/react";
import TextField from "~/components/TextField";
import Form from "~/components/Form";

function fieldReducer(
  state: LoginMutationVariables["input"],
  event: React.ChangeEvent<HTMLInputElement>
) {
  const { name, value } = event.target;
  switch (name) {
    case "username":
    case "password":
      state[name] = value;
      break;
    default:
      throw new Error("Field was not expected");
  }
  return structuredClone(state);
}

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [state, setState] = React.useReducer(fieldReducer, {
    username: "",
    password: "",
  });
  const [mutation, { error }] = useLoginMutation({
    variables: { input: state },
    errorPolicy: "all",
    async update(cache, { data }) {
      const viewer = data?.login?.user;
      if (viewer) {
        cache.writeQuery<ViewerQuery>({
          query: ViewerDocument,
          data: { __typename: "Query", viewer },
        });
      }
    },
  });
  const onSubmit = React.useCallback(async () => {
    const { data } = await mutation();
    if (data?.login?.user.id) navigate("/account");
  }, [mutation, navigate]);

  return (
    <Form onSubmit={onSubmit}>
      <div className="card">
        <h1 className="card-header">Login</h1>
        <div className="card-content flex-col">
          {error?.message && error?.message === "INCORRECT_CREDENTIALS" && (
            <div>User was not found or password was incorrect</div>
          )}
          <TextField
            name="username"
            placeholder="Email or username"
            value={state.username}
            onChange={setState}
            autoComplete="username"
            required
          />
          <TextField
            name="password"
            placeholder="Password"
            value={state.password}
            onChange={setState}
            autoComplete="current-password"
            type="password"
            required
          />
        </div>
        <div className="card-actions">
          <button type="submit" style={{ float: "right" }}>
            Login
          </button>
        </div>
      </div>
    </Form>
  );
};

export default LoginPage;
