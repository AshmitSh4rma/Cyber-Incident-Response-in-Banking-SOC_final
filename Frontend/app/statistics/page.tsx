import { ExternalLink } from "lucide-react";

/**
 * Statistics.
 *
 * Deliberately an iframe rather than a React page. The content is a standalone
 * terminal-styled document with its own palette, its own fonts and its own
 * full-viewport overlays — scanlines, matrix rain, a vignette. Rendering it
 * inside the console's styles would mean either the two designs fighting or one
 * of them being watered down; an iframe isolates it completely, so it looks
 * exactly as it does standalone while still being a page reached from the nav.
 *
 * No loading state of its own: the document opens with a boot sequence, which is
 * a better one than a spinner, and a React placeholder waiting on the iframe's
 * onLoad is one more thing that can fail to clear. The iframe paints black
 * immediately, so there is no flash to cover.
 *
 * The document lives in public/ because it is not built — one self-contained
 * file with its images embedded.
 */
export default function StatisticsPage() {
  return (
    // Cancels the shell's padding so the document runs edge to edge, and fills
    // the height left under the topbar.
    <div className="relative -m-4 h-[calc(100vh-3.25rem)] md:-m-6">
      <iframe
        src="/statistics.html"
        title="Threat ledger — what breaches cost, and what changes"
        className="h-full w-full border-0 bg-black"
      />

      <a
        href="/statistics.html"
        target="_blank"
        rel="noopener noreferrer"
        className="absolute right-3 top-3 z-10 inline-flex items-center gap-1.5 rounded border border-sev-benign/40 bg-black/80 px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-sev-benign backdrop-blur transition hover:bg-sev-benign/15"
      >
        <ExternalLink className="h-3 w-3" />
        Open full screen
      </a>
    </div>
  );
}
