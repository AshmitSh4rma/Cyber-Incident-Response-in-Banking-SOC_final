import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merge class names, letting a later Tailwind utility win over an earlier one
 * in the same group. The components under components/ui/ accept a `className`
 * from their caller, so without the merge a caller's `px-4` and the component's
 * own `px-2` would both be emitted and the winner would depend on stylesheet
 * order rather than on intent.
 *
 * This file deliberately holds only `cn`. An earlier version also exported a
 * `severityTone()` returning raw Tailwind palette classes; severity colour now
 * comes from the design tokens via lib/severity.ts, which is the single place
 * that decides what a severity looks like.
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
