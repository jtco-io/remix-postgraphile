import { gql, useQuery } from "@apollo/client";
import { useHomeScreenQuery } from "~/screens/Home/Home.generated";
import { Link } from "@remix-run/react";

export default function Index() {
  const { loading, error, data } = useHomeScreenQuery();
  return (
    <div style={{ fontFamily: "system-ui, sans-serif", lineHeight: "1.4" }}>
      <h1>Welcome to Remix</h1>
      <ul>
        {data?.allUsers?.nodes.map((node) => (
          <li key={node?.id}>{node?.name}</li>
        ))}
      </ul>
      <Link to="/admin">Admin</Link>
    </div>
  );
}
