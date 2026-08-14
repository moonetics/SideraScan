"use client";

import Image from "next/image";
import Link from "next/link";
import { AlertCircle, LockKeyhole, LogIn, UserRound } from "lucide-react";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { login } from "@/lib/api";

type LoginFormProps = {
  expired?: boolean;
};

export function LoginForm({ expired = false }: LoginFormProps) {
  const router = useRouter();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(
    expired ? "Session expired. Please login again." : null
  );
  const [isPending, setIsPending] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsPending(true);

    try {
      await login(identifier, password);
      router.replace("/");
      router.refresh();
    } catch {
      setError("Invalid credentials");
    } finally {
      setIsPending(false);
    }
  }

  return (
    <form
      className="w-full max-w-sm rounded-lg border border-white/10 bg-slate-950/45 p-6 shadow-2xl shadow-slate-950/25"
      onSubmit={handleSubmit}
    >
      <div>
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-md border border-cyan-300/20 bg-slate-950/50">
            <Image
              alt="SideraScan logo"
              className="h-10 w-10 object-contain"
              height={40}
              priority
              src="/brand/siderascan-logo-256.png"
              width={40}
            />
          </div>
          <div>
            <p className="text-sm font-medium text-cyan-200">SideraScan</p>
            <h1 className="text-2xl font-semibold tracking-normal">
              Dashboard login
            </h1>
          </div>
        </div>
        <p className="mt-2 text-sm leading-6 text-slate-300">
          Use the admin-issued dashboard credential for your account.
        </p>
      </div>

      {error ? (
        <div className="mt-5 flex items-start gap-2 rounded-md border border-rose-400/30 bg-rose-500/12 px-3 py-2 text-sm text-rose-100">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      ) : null}

      <label className="mt-5 block text-sm font-medium text-slate-200">
        Email or username
        <span className="mt-2 flex h-11 items-center gap-2 rounded-md border border-white/10 bg-slate-950/50 px-3 text-slate-300 focus-within:border-cyan-300/70">
          <UserRound className="h-4 w-4" />
          <input
            autoComplete="username"
            className="min-w-0 flex-1 bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-500"
            onChange={(event) => setIdentifier(event.target.value)}
            placeholder="email or username"
            required
            type="text"
            value={identifier}
          />
        </span>
      </label>

      <label className="mt-4 block text-sm font-medium text-slate-200">
        Password
        <span className="mt-2 flex h-11 items-center gap-2 rounded-md border border-white/10 bg-slate-950/50 px-3 text-slate-300 focus-within:border-cyan-300/70">
          <LockKeyhole className="h-4 w-4" />
          <input
            autoComplete="current-password"
            className="min-w-0 flex-1 bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-500"
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Password"
            required
            type="password"
            value={password}
          />
        </span>
      </label>

      <button
        className="mt-6 inline-flex h-11 w-full items-center justify-center gap-2 rounded-md bg-cyan-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-70"
        disabled={isPending}
        type="submit"
      >
        <LogIn className="h-4 w-4" />
        {isPending ? "Signing in" : "Login"}
      </button>

      <div className="mt-5 flex justify-center gap-3 text-xs text-slate-400">
        <Link className="transition hover:text-cyan-200" href="/legal/privacy">
          Privacy Policy
        </Link>
        <span aria-hidden="true">/</span>
        <Link className="transition hover:text-cyan-200" href="/legal/terms">
          Terms
        </Link>
      </div>
    </form>
  );
}
