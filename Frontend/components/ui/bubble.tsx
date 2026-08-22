import * as React from "react"
import { cn } from "@/lib/utils"

const Bubble = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { variant?: "default" | "muted" }
>(({ className, variant = "default", ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      "relative rounded-2xl px-4 py-3 text-sm transition-colors",
      variant === "default" && "bg-raised text-ink border border-rule",
      variant === "muted" && "bg-sunk text-muted border border-rule-soft",
      className
    )}
    {...props}
  />
))
Bubble.displayName = "Bubble"

const BubbleContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("whitespace-pre-wrap break-words leading-relaxed text-[13px]", className)}
    {...props}
  />
))
BubbleContent.displayName = "BubbleContent"

export { Bubble, BubbleContent }
