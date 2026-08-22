import * as React from "react"
import { cn } from "@/lib/utils"

const MessageContext = React.createContext<{ align: "start" | "end" }>({ align: "start" })

const MessageGroup = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex flex-col gap-2", className)}
    {...props}
  />
))
MessageGroup.displayName = "MessageGroup"

const Message = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { align?: "start" | "end" }
>(({ className, align = "start", ...props }, ref) => (
  <MessageContext.Provider value={{ align }}>
    <div
      ref={ref}
      className={cn(
        "group/message flex gap-3",
        align === "end" ? "flex-row-reverse" : "flex-row",
        className
      )}
      {...props}
    />
  </MessageContext.Provider>
))
Message.displayName = "Message"

const MessageAvatar = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => {
  const { align } = React.useContext(MessageContext)
  return (
    <div
      ref={ref}
      className={cn(
        "flex shrink-0 items-end pb-1",
        align === "start" ? "mr-1" : "ml-1",
        className
      )}
      {...props}
    />
  )
})
MessageAvatar.displayName = "MessageAvatar"

const MessageContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => {
  const { align } = React.useContext(MessageContext)
  return (
    <div
      ref={ref}
      className={cn(
        "flex max-w-[80%] flex-col gap-1.5",
        align === "end" ? "items-end" : "items-start",
        className
      )}
      {...props}
    />
  )
})
MessageContent.displayName = "MessageContent"

const MessageHeader = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex items-center gap-2 text-[10px] font-semibold tracking-wide uppercase text-faint px-1", className)}
    {...props}
  />
))
MessageHeader.displayName = "MessageHeader"

const MessageFooter = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex items-center gap-2 text-[10px] text-faint px-1", className)}
    {...props}
  />
))
MessageFooter.displayName = "MessageFooter"

export { Message, MessageGroup, MessageAvatar, MessageContent, MessageHeader, MessageFooter }
