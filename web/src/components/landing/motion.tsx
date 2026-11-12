"use client";

import { useEffect, useRef } from "react";

/**
 * Scroll motion for the landing page. The hero animates in pure CSS (globals.css) so the first paint
 * never waits on JavaScript; GSAP loads after the page is interactive and only handles what scrolls in:
 *   data-reveal   a block that rises in
 *   data-stagger  a container whose children rise in one after another
 *   data-bar      a bar that grows from the left
 *   data-type     a terminal whose lines print one at a time
 * Anything already on screen when GSAP arrives is left alone (no hide-then-show flash), finished tweens
 * clear their inline styles so no element keeps a compositor layer, and reduced motion skips it all.
 */
export function LandingMotion({ children }: { children: React.ReactNode }) {
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    let cancelled = false;
    let revert: (() => void) | undefined;

    (async () => {
      const [{ gsap }, { ScrollTrigger }] = await Promise.all([import("gsap"), import("gsap/ScrollTrigger")]);
      const el = root.current;
      if (cancelled || !el) return;
      gsap.registerPlugin(ScrollTrigger);

      const ctx = gsap.context(() => {
        const below = (n: Element) => n.getBoundingClientRect().top > window.innerHeight;
        const pick = (sel: string) => gsap.utils.toArray<HTMLElement>(sel, el).filter(below);
        const done = "transform,opacity,visibility,clipPath";

        const rise = pick("[data-reveal], [data-stagger] > *");
        gsap.set(rise, { autoAlpha: 0, y: 32 });
        ScrollTrigger.batch(rise, {
          start: "top 90%",
          once: true,
          onEnter: (batch) =>
            gsap.to(batch, { autoAlpha: 1, y: 0, duration: 0.8, ease: "power3.out", stagger: 0.08, clearProps: done }),
        });

        const bars = pick("[data-bar]");
        gsap.set(bars, { scaleX: 0, transformOrigin: "left center" });
        ScrollTrigger.batch(bars, {
          start: "top 90%",
          once: true,
          onEnter: (batch) => gsap.to(batch, { scaleX: 1, duration: 1.1, ease: "power4.out", stagger: 0.12, clearProps: done }),
        });

        pick("[data-type]").forEach((term) => {
          const lines = Math.max(1, (term.textContent ?? "").split("\n").length);
          gsap.set(term, { clipPath: "inset(0 0 100% 0)" });
          ScrollTrigger.create({
            trigger: term,
            start: "top 85%",
            once: true,
            onEnter: () =>
              gsap.to(term, { clipPath: "inset(0 0 0% 0)", duration: lines * 0.3, ease: `steps(${lines})`, clearProps: done }),
          });
        });
      }, el);
      revert = () => ctx.revert();
    })();

    return () => {
      cancelled = true;
      revert?.();
    };
  }, []);

  return <div ref={root}>{children}</div>;
}
