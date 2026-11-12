"use client";

import Link from "next/link";
import { flushSync } from "react-dom";
import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { useId, useSyncExternalStore } from "react";
import { cn } from "@/lib/utils";

/*
 * The Farrier mark: a horseshoe drawn as an open renewal arc. Its seven nail holes sit
 * 32° apart like ticks on a cycle. A farrier re-shoes a working horse every four to six
 * weeks; Farrier re-certifies a working machine on the same kind of rhythm.
 */
export const HORSESHOE_PATH = "M7.38 17.41A7.5 7.5 0 1 1 16.62 17.41";
export const NAIL_HOLES: [number, number][] = [
  [4.54, 12.28],
  [5.26, 8.21],
  [8.03, 5.14],
  [12, 4],
  [15.97, 5.14],
  [18.74, 8.21],
  [19.46, 12.28],
];

export function LogoMark({ className }: { className?: string }) {
  const id = useId();
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden className={cn("size-6", className)}>
      <mask id={id} maskUnits="userSpaceOnUse" x="0" y="0" width="24" height="24">
        <rect width="24" height="24" fill="#fff" />
        {NAIL_HOLES.map(([cx, cy]) => (
          <circle key={cx} cx={cx} cy={cy} r="0.85" fill="#000" />
        ))}
      </mask>
      <path d={HORSESHOE_PATH} stroke="currentColor" strokeWidth="3.6" mask={`url(#${id})`} />
    </svg>
  );
}

export function Logo({ href = "/", className }: { href?: string; className?: string }) {
  return (
    <Link href={href} className={cn("inline-flex items-center gap-2 text-base font-semibold tracking-tight", className)}>
      <LogoMark />
      <span>Farrier</span>
    </Link>
  );
}

/** GitHub mark (lucide no longer ships brand icons). */
export function GithubIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden className={cn("size-4", className)}>
      <path d="M12 .5C5.65.5.5 5.65.5 12a11.5 11.5 0 0 0 7.86 10.92c.58.1.79-.25.79-.56v-2c-3.2.7-3.87-1.36-3.87-1.36-.52-1.33-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.15.08 1.76 1.19 1.76 1.19 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.69 5.39-5.25 5.67.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5Z" />
    </svg>
  );
}

const noop = () => () => {};

/** Crossfade the whole page between themes where the browser supports View Transitions. */
function switchTheme(setTheme: (t: string) => void, value: string) {
  const doc = document as Document & { startViewTransition?: (cb: () => void) => unknown };
  if (!doc.startViewTransition || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    setTheme(value);
    return;
  }
  doc.startViewTransition(() => flushSync(() => setTheme(value)));
}

export function ThemeToggle({ className }: { className?: string }) {
  const { theme, setTheme } = useTheme();
  const mounted = useSyncExternalStore(noop, () => true, () => false);
  const options = [
    { value: "light", icon: Sun, label: "Light" },
    { value: "system", icon: Monitor, label: "System" },
    { value: "dark", icon: Moon, label: "Dark" },
  ];
  return (
    <div role="radiogroup" aria-label="Theme" className={cn("inline-flex rounded-full border p-1", className)}>
      {options.map(({ value, icon: Icon, label }) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={mounted && theme === value}
          aria-label={label}
          onClick={() => switchTheme(setTheme, value)}
          className={cn(
            "rounded-full p-1 text-muted-foreground transition-colors hover:text-foreground",
            mounted && theme === value && "bg-foreground text-background hover:text-background",
          )}
        >
          <Icon className="size-3.5" />
        </button>
      ))}
    </div>
  );
}
