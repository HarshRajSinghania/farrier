import { redirect } from "next/navigation";

// The install is the dashboard; the landing page and docs live in site/.
export default function Home() {
  redirect("/dashboard");
}
