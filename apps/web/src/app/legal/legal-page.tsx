import Image from "next/image";
import Link from "next/link";
import type { ReactNode } from "react";

type LegalPageProps = {
  children: ReactNode;
  description: string;
  effectiveDate: string;
  title: string;
};

export function LegalPage({
  children,
  description,
  effectiveDate,
  title,
}: LegalPageProps) {
  return (
    <main className="min-h-screen px-4 py-8 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-5xl">
        <header className="rounded-lg border border-white/10 bg-slate-950/35 p-5 shadow-2xl shadow-slate-950/20">
          <div className="flex flex-col justify-between gap-5 md:flex-row md:items-center">
            <Link className="flex items-center gap-3" href="/login">
              <div className="flex h-11 w-11 items-center justify-center rounded-md border border-cyan-300/20 bg-slate-950/45">
                <Image
                  alt="SideraScan logo"
                  className="h-9 w-9 object-contain"
                  height={36}
                  priority
                  src="/brand/siderascan-logo-256.png"
                  width={36}
                />
              </div>
              <div>
                <p className="text-sm text-slate-300">SideraScan</p>
                <h1 className="text-xl font-semibold text-slate-100">
                  {title}
                </h1>
              </div>
            </Link>

            <nav className="flex flex-wrap gap-2 text-sm">
              <Link
                className="rounded-md border border-white/10 px-3 py-2 text-slate-200 transition hover:bg-white/8"
                href="/legal/privacy"
              >
                Privacy
              </Link>
              <Link
                className="rounded-md border border-white/10 px-3 py-2 text-slate-200 transition hover:bg-white/8"
                href="/legal/terms"
              >
                Terms
              </Link>
              <Link
                className="rounded-md border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 font-semibold text-cyan-100 transition hover:bg-cyan-400/16"
                href="/login"
              >
                Dashboard
              </Link>
            </nav>
          </div>

          <div className="mt-6 border-t border-white/10 pt-5">
            <p className="text-sm font-medium text-cyan-200">
              Effective {effectiveDate}
            </p>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">
              {description}
            </p>
          </div>
        </header>

        <article className="mt-6 space-y-4 rounded-lg border border-white/10 bg-[#172842] p-5 shadow-2xl shadow-slate-950/20 md:p-7">
          {children}
        </article>

        <footer className="py-8 text-center text-xs text-slate-500">
          Developed by Squad Limpul © 2026. All rights reserved.
        </footer>
      </div>
    </main>
  );
}

export function LegalSection({
  children,
  title,
}: {
  children: ReactNode;
  title: string;
}) {
  return (
    <section className="rounded-lg border border-white/10 bg-slate-950/24 p-4">
      <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
      <div className="mt-3 space-y-3 text-sm leading-6 text-slate-300">
        {children}
      </div>
    </section>
  );
}

export function LegalList({ items }: { items: string[] }) {
  return (
    <ul className="space-y-2">
      {items.map((item) => (
        <li className="rounded-md border border-white/8 bg-white/5 px-3 py-2" key={item}>
          {item}
        </li>
      ))}
    </ul>
  );
}
