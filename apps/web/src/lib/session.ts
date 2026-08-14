import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getMe } from "./api";

export async function getCookieHeader() {
  const cookieStore = await cookies();
  return cookieStore.toString();
}

export async function requireCurrentUser(cookieHeader: string) {
  try {
    const session = await getMe(cookieHeader);
    return session.user;
  } catch {
    redirect("/login?expired=1");
  }
}

