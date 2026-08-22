"use client";

import { createContext, useCallback, useContext, useSyncExternalStore } from "react";

/**
 * Detail level.
 *
 * The console has two audiences with opposite needs. A risk officer or an executive
 * wants four numbers and a sentence. An analyst wants the technique id, the control
 * id, the CVSS vector, the engine list and the raw record.
 *
 * Serving both by showing everything to everyone means the second audience is fine
 * and the first is lost. So the default is **Overview** — plain language, no
 * identifiers, no jargon — and one control reveals the rest. Nothing is deleted;
 * it is one click away, and the click is labelled in words rather than hidden
 * behind an icon.
 *
 * Implemented over useSyncExternalStore rather than useState-plus-effect. The
 * preference lives in localStorage, which is an external system: reading it inside
 * an effect and calling setState costs an extra render pass, risks a hydration
 * mismatch, and — the reason that actually matters — would not notice the same
 * user changing the level in another tab. Subscribing gets all three right.
 */

export type DetailLevel = "overview" | "analyst";

const STORAGE_KEY = "sentra.detail";
const DEFAULT: DetailLevel = "overview";

function isLevel(value: unknown): value is DetailLevel {
  return value === "overview" || value === "analyst";
}

/* ─── The store ───────────────────────────────────────────────────────────── */

const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // `storage` fires in *other* tabs, so this is what keeps two open windows in
  // step. Same-tab writes call notify() directly.
  window.addEventListener("storage", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", listener);
  };
}

function read(): DetailLevel {
  // A URL override wins over the stored preference, so a link can open the
  // console at a known detail level — useful for a demo, a bug report, or a
  // reproducible screenshot.  ?detail=analyst  ·  ?detail=overview
  try {
    const fromUrl = new URLSearchParams(window.location.search).get("detail");
    if (isLevel(fromUrl)) return fromUrl;
  } catch {
    /* fall through to the stored preference */
  }

  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (isLevel(stored)) return stored;
  } catch {
    // Private browsing, or storage disabled. The default is fine.
  }

  return DEFAULT;
}

function write(next: DetailLevel): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // Not worth surfacing: the choice still applies for this session, it just
    // will not survive a reload.
  }
  notify();
}

/* ─── The hook ────────────────────────────────────────────────────────────── */

type Ctx = {
  level: DetailLevel;
  isAnalyst: boolean;
  setLevel: (level: DetailLevel) => void;
  toggle: () => void;
};

const DetailContext = createContext<Ctx | null>(null);

export function DetailProvider({ children }: { children: React.ReactNode }) {
  // The server has no localStorage and no URL search params it should trust for
  // this, so it always renders the default and the client corrects on hydration.
  const level = useSyncExternalStore(subscribe, read, () => DEFAULT);

  const setLevel = useCallback((next: DetailLevel) => write(next), []);
  const toggle = useCallback(
    () => write(level === "analyst" ? "overview" : "analyst"),
    [level],
  );

  return (
    <DetailContext.Provider value={{ level, isAnalyst: level === "analyst", setLevel, toggle }}>
      {children}
    </DetailContext.Provider>
  );
}

export function useDetail(): Ctx {
  const ctx = useContext(DetailContext);
  if (!ctx) {
    // Failing loudly beats silently rendering the overview: a panel that quietly
    // hides its technical detail because it was mounted outside the provider is
    // very hard to notice.
    throw new Error("useDetail must be used inside <DetailProvider>");
  }
  return ctx;
}
