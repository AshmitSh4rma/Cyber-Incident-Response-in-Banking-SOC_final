"use client"

import { useState } from "react"
import { Send, Bot, RotateCcw, Sparkles } from "lucide-react"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Bubble, BubbleContent } from "@/components/ui/bubble"
import {
  Message,
  MessageAvatar,
  MessageContent,
  MessageHeader,
  MessageFooter,
} from "@/components/ui/message"
import TextType from "@/components/ui/TextType"

type ChatMessage = {
  id: string
  role: "user" | "assistant"
  content: string
  timestamp: string
}

const SOC_PROMPTS = [
  "Ask Sentinel AI to analyze telemetry and active threats...",
  "Query regulatory compliance deadlines and breach obligations...",
  "Generate an executive incident response report...",
  "Correlate multi-stage attack campaigns across hosts...",
  "Formulate MITRE ATT&CK containment actions..."
]

export default function AgenticAiPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState("")

  const handleReset = () => {
    setMessages([])
    setInput("")
  }

  const submitMessage = (textToSend: string) => {
    const trimmed = textToSend.trim()
    if (!trimmed) return

    const newMsg: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: trimmed,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    }

    setMessages((prev) => [...prev, newMsg])
    setInput("")

    // Simulated AI response
    setTimeout(() => {
      const aiReply: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: `I am analyzing your query regarding "${trimmed.slice(0, 40)}${trimmed.length > 40 ? "..." : ""}". Gathering real-time telemetry from active incident queues and correlated campaigns.`,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      }
      setMessages((prev) => [...prev, aiReply])
    }, 900)
  }

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault()
    submitMessage(input)
  }

  return (
    <div className="flex flex-col h-[calc(100vh-65px)] mx-auto max-w-[1200px]">
      <header className="shrink-0 flex flex-wrap items-center justify-between gap-4 py-6 px-4">
        <div className="space-y-1.5">
          <p className="eyebrow">Agentic AI</p>
          <h1 className="text-2xl font-semibold tracking-tight text-ink flex items-center gap-2">
            <Bot className="h-6 w-6 text-accent" />
            Sentinel Assistant
          </h1>
          <p className="max-w-2xl text-xs leading-relaxed text-muted">
            Your autonomous SOC analyst for incident triage, threat correlation, and compliance response.
          </p>
        </div>

        {messages.length > 0 && (
          <button
            onClick={handleReset}
            className="inline-flex items-center gap-1.5 rounded-md border border-rule bg-surface px-3 py-1.5 text-xs font-medium text-muted hover:text-ink hover:bg-raised transition-colors shadow-sm"
            title="Reset conversation"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            Reset chat
          </button>
        )}
      </header>

      {/* Chat / Hero Area */}
      <div className="flex-1 overflow-y-auto px-4 pb-4 flex flex-col justify-start">
        {messages.length === 0 ? (
          <div className="my-auto flex flex-col items-center justify-center text-center p-6 space-y-4">
            <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-accent/10 border border-accent/30 text-accent shadow-[0_0_30px_rgba(0,240,255,0.15)] mb-2">
              <Sparkles className="h-7 w-7" />
            </div>

            <div className="max-w-2xl">
              <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-ink mb-2">
                How can Sentinel assist your SOC today?
              </h2>
              <div className="text-sm sm:text-base text-accent font-medium min-h-[32px] flex items-center justify-center">
                <TextType
                  text={SOC_PROMPTS}
                  typingSpeed={45}
                  pauseDuration={2200}
                  deletingSpeed={25}
                  loop={true}
                  showCursor={true}
                  cursorCharacter="▋"
                  cursorClassName="text-accent ml-1"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 max-w-xl w-full pt-4">
              {SOC_PROMPTS.slice(0, 4).map((prompt, idx) => (
                <button
                  key={idx}
                  onClick={() => submitMessage(prompt)}
                  className="rounded-lg border border-rule-soft bg-surface/60 hover:bg-surface hover:border-accent-deep/60 p-2.5 text-left text-xs text-muted hover:text-ink transition-all shadow-sm group flex items-center justify-between gap-2"
                >
                  <span>"{prompt.replace(/\.\.\.$/, "")}"</span>
                  <Send className="h-3 w-3 text-faint group-hover:text-accent transition-colors shrink-0" />
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {messages.map((msg, index) => {
              const isUser = msg.role === "user"
              const showAvatar =
                index === messages.length - 1 || messages[index + 1]?.role !== msg.role

              return (
                <Message key={msg.id} align={isUser ? "end" : "start"}>
                  {showAvatar && (
                    <MessageAvatar>
                      <Avatar>
                        <AvatarFallback className={isUser ? "bg-accent text-sunk" : "bg-raised text-accent"}>
                          {isUser ? "U" : <Bot className="h-4 w-4" />}
                        </AvatarFallback>
                      </Avatar>
                    </MessageAvatar>
                  )}
                  {!showAvatar && <div className="w-8" />}

                  <MessageContent>
                    <MessageHeader>{isUser ? "You" : "Sentinel AI"}</MessageHeader>
                    <Bubble variant={isUser ? "default" : "muted"}>
                      <BubbleContent>{msg.content}</BubbleContent>
                    </Bubble>
                    <MessageFooter>{msg.timestamp}</MessageFooter>
                  </MessageContent>
                </Message>
              )
            })}
          </div>
        )}
      </div>

      {/* Input Area */}
      <div className="shrink-0 p-4 border-t border-rule-soft bg-ground">
        <form
          onSubmit={handleSend}
          className="relative flex items-center w-full max-w-4xl mx-auto rounded-lg border border-rule bg-surface p-1.5 shadow-sm transition-all focus-within:border-accent focus-within:ring-1 focus-within:ring-accent/40"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask Sentinel AI to analyze an alert, generate a report, or contain a threat..."
            className="flex-1 bg-transparent px-3 py-2 text-sm text-ink placeholder-faint border-0 outline-none focus:outline-none focus:ring-0 ring-0 focus-visible:outline-none focus-visible:ring-0 shadow-none"
            style={{ outline: "none", boxShadow: "none" }}
          />
          <button
            type="submit"
            disabled={!input.trim()}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent text-sunk transition hover:bg-accent-deep disabled:opacity-30 disabled:hover:bg-accent focus:outline-none focus:ring-0"
          >
            <Send className="h-3.5 w-3.5" />
          </button>
        </form>
      </div>
    </div>
  )
}

