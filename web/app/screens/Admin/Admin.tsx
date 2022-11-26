import { useAdminScreenQuery } from "~/screens/Admin/Admin.generated";

export default function AdminScreen() {
  const { data } = useAdminScreenQuery();
  console.log(data);
  return <div>Admin screen</div>;
}
