import Image from "next/image";

export default function Loading() {
  return (
    <main className="min-h-screen px-4 py-4 sm:px-6 lg:px-8">
      <div className="grid w-full gap-6 lg:grid-cols-[260px_minmax(0,1fr)]">
        <aside className="rounded-lg border border-white/10 bg-slate-950/35 p-5 shadow-2xl shadow-slate-950/20 lg:sticky lg:top-4 lg:h-[calc(100vh-2rem)]">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-md border border-cyan-300/20 bg-slate-950/45">
              <Image
                alt="SideraScan logo"
                className="h-9 w-9 object-contain opacity-70"
                height={36}
                priority
                src="/brand/siderascan-logo-256.png"
                width={36}
              />
            </div>
            <div className="min-w-0 flex-1">
              <div className="h-3 w-20 animate-pulse rounded bg-white/10" />
              <div className="mt-2 h-5 w-28 animate-pulse rounded bg-white/10" />
            </div>
          </div>
          <div className="mt-6 h-16 animate-pulse rounded-md bg-white/8" />
          <div className="mt-8 grid gap-2">
            {Array.from({ length: 9 }).map((_, index) => (
              <div
                className="h-9 animate-pulse rounded-md bg-white/8"
                key={index}
              />
            ))}
          </div>
        </aside>

        <section className="min-w-0 rounded-lg border border-white/10 bg-slate-950/30 p-6 shadow-2xl shadow-slate-950/20 lg:min-h-[calc(100vh-2rem)]">
          <div className="mb-6 flex justify-end">
            <div className="h-10 w-24 animate-pulse rounded-md bg-white/10" />
          </div>

          <div className="h-1 overflow-hidden rounded-full bg-slate-800">
            <div className="h-full w-1/2 animate-[pulse_1s_ease-in-out_infinite] rounded-full bg-cyan-400" />
          </div>

          <div className="mt-12 flex items-start justify-between gap-6">
            <div className="min-w-0 flex-1">
              <div className="h-4 w-28 animate-pulse rounded bg-cyan-300/20" />
              <div className="mt-4 h-8 w-56 animate-pulse rounded-md bg-white/10" />
              <div className="mt-4 h-4 w-[34rem] max-w-full animate-pulse rounded-md bg-white/8" />
              <div className="mt-2 h-4 w-[24rem] max-w-full animate-pulse rounded-md bg-white/8" />
            </div>
            <div className="hidden h-16 w-36 animate-pulse rounded-md border border-white/10 bg-white/8 sm:block" />
          </div>

          <div className="mt-8 border-t border-white/10 pt-6">
            <div className="rounded-lg border border-white/10 bg-white/5 p-4">
              <div className="h-5 w-48 animate-pulse rounded bg-white/10" />
              <div className="mt-3 h-4 w-80 max-w-full animate-pulse rounded bg-white/8" />
              <div className="mt-5 grid gap-3 lg:grid-cols-4">
                {Array.from({ length: 4 }).map((_, index) => (
                  <div
                    className="h-10 animate-pulse rounded-md bg-slate-950/60"
                    key={index}
                  />
                ))}
              </div>
              <div className="mt-4 h-10 w-28 animate-pulse rounded-md bg-cyan-400/30" />
            </div>
          </div>

          <div className="mt-6 rounded-lg border border-white/10 bg-white/5">
            <div className="flex items-center justify-between gap-4 border-b border-white/10 p-4">
              <div>
                <div className="h-5 w-44 animate-pulse rounded bg-white/10" />
                <div className="mt-3 h-4 w-80 max-w-full animate-pulse rounded bg-white/8" />
              </div>
              <div className="h-10 w-48 animate-pulse rounded-md bg-slate-950/60" />
            </div>
            {Array.from({ length: 4 }).map((_, index) => (
              <div
                className="grid gap-6 border-b border-white/10 p-4 last:border-b-0 md:grid-cols-[1.3fr_1fr_1fr_240px]"
                key={index}
              >
                <div>
                  <div className="h-5 w-52 animate-pulse rounded bg-white/10" />
                  <div className="mt-3 h-4 w-64 max-w-full animate-pulse rounded bg-white/8" />
                  <div className="mt-2 h-3 w-48 max-w-full animate-pulse rounded bg-white/8" />
                </div>
                <div className="space-y-3">
                  <div className="h-4 w-28 animate-pulse rounded bg-white/8" />
                  <div className="h-6 w-20 animate-pulse rounded bg-cyan-300/20" />
                </div>
                <div className="space-y-3">
                  <div className="h-4 w-24 animate-pulse rounded bg-white/8" />
                  <div className="h-4 w-32 animate-pulse rounded bg-white/8" />
                </div>
                <div className="space-y-3">
                  <div className="h-10 animate-pulse rounded-md bg-slate-950/60" />
                  <div className="h-10 animate-pulse rounded-md bg-cyan-400/25" />
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}
