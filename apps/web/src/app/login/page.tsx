import { redirect } from "next/navigation";
import { cookies } from "next/headers";
import { getMe } from "@/lib/api";
import { LoginForm } from "./login-form";

type LoginPageProps = {
  searchParams: Promise<{
    expired?: string;
  }>;
};

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const cookieStore = await cookies();
  const cookieHeader = cookieStore.toString();
  let hasSession = false;

  try {
    await getMe(cookieHeader);
    hasSession = true;
  } catch {
    hasSession = false;
  }

  if (hasSession) {
    redirect("/");
  }

  const params = await searchParams;

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-10">
      <LoginForm expired={params.expired === "1"} />
    </main>
  );
}
