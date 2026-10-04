'use client';

import { useEffect } from 'react';

const HIDE: Record<string, string> = { up: 'translateY(32px)', left: 'translateX(-36px)', right: 'translateX(36px)', scale: 'scale(.94)' };

/**
 * Landing-page motion, attribute driven: data-r (reveal on scroll, data-d delay), data-count,
 * data-fill, data-bar, data-draw, data-glow (cursor spotlight), data-tilt, data-hs (hero card
 * swing), plus the scroll progress bar, nav tint and cursor glow. Off under reduced motion.
 */
export function LandingMotion() {
  useEffect(() => {
    const root = document.querySelector<HTMLElement>('.home');
    if (!root) return;
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const C: (() => void)[] = [];
    const on = <K extends keyof WindowEventMap>(t: EventTarget, e: K | string, f: (ev: never) => void, o?: AddEventListenerOptions) => {
      t.addEventListener(e, f as EventListener, o);
      C.push(() => t.removeEventListener(e, f as EventListener, o));
    };
    const all = (sel: string) => [...root.querySelectorAll<HTMLElement>(sel)];
    const ease = (t: number) => 1 - Math.pow(1 - t, 4);
    let dead = false;

    const count = (el: HTMLElement) => {
      const to = +el.dataset.count!;
      if (reduce) return;
      const t0 = performance.now();
      const step = (t: number) => {
        const p = Math.min(1, (t - t0) / 1600);
        el.textContent = Math.round(to * ease(p)).toLocaleString('en-US');
        if (p < 1 && !dead) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    };
    if (!reduce) {
      all('[data-r]').forEach((el) => {
        const d = +(el.dataset.d || 0);
        el.style.opacity = '0';
        el.style.transform = HIDE[el.dataset.r!] || HIDE.up;
        el.style.filter = 'blur(8px)';
        el.style.transition = `opacity .9s cubic-bezier(.2,.7,.2,1) ${d}ms, transform .9s cubic-bezier(.2,.7,.2,1) ${d}ms, filter .9s ease ${d}ms`;
      });
      all('[data-fill]').forEach((el) => { el.style.width = '0%'; el.style.transition = 'width 1.4s cubic-bezier(.2,.7,.2,1) .2s'; });
      all('[data-bar]').forEach((el, i) => { el.style.height = '0%'; el.style.transition = `height .9s cubic-bezier(.2,.7,.2,1) ${i * 40}ms`; });
      all('[data-draw]').forEach((el) => { el.style.transform = el.dataset.draw === 'y' ? 'scaleY(0)' : 'scaleX(0)'; el.style.transition = 'transform 1.6s cubic-bezier(.2,.7,.2,1)'; });
      all('[data-count]').forEach((el) => (el.textContent = '0'));
    }
    let pending = all('[data-r],[data-fill],[data-bar],[data-draw],[data-count]');
    const reveal = (el: HTMLElement) => {
      const d = el.dataset;
      if (d.r) { el.style.opacity = '1'; el.style.transform = 'none'; el.style.filter = 'none'; }
      if (d.fill) el.style.width = d.fill + '%';
      if (d.bar) el.style.height = d.bar + '%';
      if (d.draw) el.style.transform = 'none';
      if (d.count) count(el);
    };
    const check = () => {
      if (!pending.length) return;
      const lim = innerHeight * 0.92;
      pending = pending.filter((el) => (el.getBoundingClientRect().top < lim ? (reveal(el), false) : true));
    };
    requestAnimationFrame(() => requestAnimationFrame(check));
    const iv = setInterval(check, 400);
    C.push(() => clearInterval(iv));

    const prog = document.getElementById('home-prog');
    const nav = document.getElementById('home-nav');
    const swing = all('[data-hs]');
    let ticking = false;
    on(window, 'scroll', () => {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        ticking = false;
        check();
        if (!reduce) swing.forEach((el) => (el.style.transform = `rotateY(${(+el.dataset.hs! * Math.max(0, 1 - scrollY / 420)).toFixed(2)}deg)`));
        const h = document.documentElement.scrollHeight - innerHeight;
        if (prog) prog.style.transform = `scaleX(${h > 0 ? scrollY / h : 0})`;
        if (nav) nav.style.background = scrollY > 40 ? 'rgb(0 0 0 / 82%)' : 'rgb(0 0 0 / 60%)';
      });
    }, { passive: true });

    all('[data-glow]').forEach((el) => on(el, 'mousemove', (e: MouseEvent) => {
      const r = el.getBoundingClientRect();
      el.style.setProperty('--gx', e.clientX - r.left + 'px');
      el.style.setProperty('--gy', e.clientY - r.top + 'px');
    }));
    if (!reduce) all('[data-tilt]').forEach((el) => {
      const k = +el.dataset.tilt!;
      on(el, 'mousemove', (e: MouseEvent) => {
        const r = el.getBoundingClientRect();
        const x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5;
        el.style.transform = `perspective(1000px) rotateX(${(-y * k).toFixed(2)}deg) rotateY(${(x * k).toFixed(2)}deg)`;
      });
      on(el, 'mouseleave', () => (el.style.transform = 'none'));
    });

    // Cursor glow eases toward the pointer.
    const cur = document.getElementById('home-cursor');
    let mx = -999, my = -999, cx = -999, cy = -999, raf = 0;
    on(window, 'mousemove', (e: MouseEvent) => { mx = e.clientX; my = e.clientY; }, { passive: true });
    const loop = () => {
      cx += (mx - cx) * 0.12;
      cy += (my - cy) * 0.12;
      if (cur) cur.style.transform = `translate3d(${cx.toFixed(1)}px,${cy.toFixed(1)}px,0)`;
      raf = requestAnimationFrame(loop);
    };
    if (!reduce) raf = requestAnimationFrame(loop);
    C.push(() => cancelAnimationFrame(raf));

    return () => {
      dead = true;
      C.forEach((f) => f());
    };
  }, []);
  return null;
}

/** The hero's install command with a working copy button. */
export function CopyCommand({ cmd }: { cmd: string }) {
  return (
    <button
      type="button"
      aria-label="Copy install command"
      onClick={(e) => {
        const b = e.currentTarget;
        navigator.clipboard?.writeText(cmd).then(() => {
          b.dataset.copied = '1';
          setTimeout(() => delete b.dataset.copied, 1500);
        }).catch(() => {});
      }}
      className="home-copy"
    >
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
        <rect width="14" height="14" x="8" y="8" rx="2" />
        <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
      </svg>
    </button>
  );
}
