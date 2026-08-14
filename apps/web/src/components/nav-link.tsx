"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ComponentType, useState } from "react";

type NavLinkProps = {
  href: string;
  icon: ComponentType<{ className?: string }>;
  label: string;
};

export function NavLink({ href, icon: Icon, label }: NavLinkProps) {
  const pathname = usePathname();
  const [isPending, setIsPending] = useState(false);
  const isActive = href === "/" ? pathname === "/" : pathname.startsWith(href);

  return (
    <Link
      className={`flex items-center gap-2 rounded-md px-3 py-2 transition hover:bg-white/8 ${
        isActive ? "bg-white/8 text-cyan-100" : ""
      } ${isPending ? "opacity-70" : ""}`}
      href={href}
      onClick={() => {
        if (pathname !== href) {
          setIsPending(true);
        }
      }}
    >
      <Icon className="h-4 w-4" />
      <span className="min-w-0 flex-1">{label}</span>
      {isPending ? (
        <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-300" />
      ) : null}
    </Link>
  );
}
