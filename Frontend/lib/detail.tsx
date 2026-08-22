"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";

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
 * The choice persists, because an analyst should set it once and never again.
 */

export type DetailLevel = "overview" | "analyst";

const STORAGE_KEY = "sentra.detail";

type Ctx = {
  level: DetailLevel;
  isAnalyst: boolean;
  setLevel: (level: DetailLevel) => void;
  toggle: () => void;
};

const DetailContext = createContext<Ctx>({
  level: "overview",
  isAnalyst: false,
  setLevel: () => {},
  toggle: () => {},
});

export function DetailProvider({ children }: { children: React.ReactNode }) {
  // Start at overview on the server and the first client paint so the two agree;
  // the stored preference is applied immediately after mount.
  const [level, setLevelState] = useState<DetailLevel>("overview");

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (stored === "analyst" || stored === "overview") setLevelState(stored);
    } catch {
      // Private browsing or storage disabled — the default is fine.
    }
  }, []);

  const setLevel = useCallback((next: DetailLevel) => {
    setLevelState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* not worth surfacing */
    }
  }, []);

  const toggle = useCallback(
    () => setLevel(level === "analyst" ? "overview" : "analyst"),
    [level, setLevel],
  );

  return (
    <DetailContext.Provider value={{ level, isAnalyst: level === "analyst", setLevel, toggle }}>
      {children}
    </DetailContext.Provider>
  );
}

export function useDetail(): Ctx {
  return useContext(DetailContext);
}

/** Render children only for analysts. */
export function AnalystOnly({ children }: { children: React.ReactNode }) {
  const { isAnalyst } = useDetail();
  return isAnalyst ? <>{children}</> : null;
}
