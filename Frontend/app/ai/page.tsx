"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Bot, RotateCcw, Send, ServerCrash, Sparkles, TriangleAlert } from "lucide-react";

import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Bubble, BubbleContent } from "@/components/ui/bubble";
import {
  Message,
  MessageAvatar,
  MessageContent,
  MessageFooter,
  MessageHeader,
} from "@/components/ui/message";
import TextType from "@/components/ui/TextType";
import { EmptyState } from "@/components/soc/primitives";

/**
 * Ask SENTRA.
 *
 * Answers come from prototype_ai_chat, which retrieves the actual stored
 * incidents and campaigns and then verifies every claim in the generated text
 * against them, dropping anything the records do not support. So each answer
 * carries what it was based on: the evidence it cites, how many records it
 * considered, and whether a model was involved at all.
 *
 * This page never writes an answer of its own. An earlier revision replied on a
 * timer with "I am analyzing your query regarding …", which reads as a working
 * assistant and is a fabrication — the one thing a console built to avoid
 * unfounded conclusions must not ship.
 */

type Evidence = { type: string; id: string };

type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  /** Assistant only. Absent on a failure, which is rendered as a failure. */
  evidence?: Evidence[];
  recordsConsidered?: number;
  aiUsed?: boolean;
  model?: string | null;
  grounding?: string | null;
  failed?: boolean;
};

type Health = {
  status: string;
  database: string;
  gemini: string;
  model?: string | null;
  detail?: string;
};

const STARTERS = [
  "How many incidents are open right now?",
  "Which incident has the highest CVSS score?",
  "What campaigns have been correlated?",
  "Summarise the MITRE techniques seen so far",
];

const TYPED_LINES = [
  "How many incidents are open right now?",
  "Which incident has the highest CVSS score?",
  "What campaigns have been correlated?",
  "Which users are most at risk?",
  "Summarise the MITRE techniques seen so far",
];

function now(): string {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** Link evidence to the screen that shows it, where there is one. */
function evidenceHref(item: Evidence): string | null {
  if (item.type === "incident") return `/incident/${item.id}`;
  if (item.type === "campaign") return `/campaigns/${item.id}`;
  return null;
}

export default function AskSentraPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const streamEnd = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await fetch("/api/ai/health", { cache: "no-store" });
        const data = (await res.json()) as Health;
        if (alive) setHealth(data);
      } catch {
        if (alive) {
          setHealth({ status: "unreachable", database: "unknown", gemini: "unknown" });
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    streamEnd.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  const unreachable = health?.status === "unreachable";
  const noDatabase = !!health && health.status !== "unreachable" && health.database !== "connected";
  const answerable = !!health && !unreachable && !noDatabase;

  const reset = () => {
    setMessages([]);
    setInput("");
    setSessionId(null);
  };

  const submit = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || sending || !answerable) return;

    setMessages((prev) => [
      ...prev,
      { id: `u-${prev.length}-${trimmed.length}`, role: "user", content: trimmed, timestamp: now() },
    ]);
    setInput("");
    setSending(true);

    try {
      const res = await fetch("/api/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: trimmed, session_id: sessionId }),
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        const detail =
          typeof data?.detail === "string"
            ? data.detail
            : `The service answered ${res.status} and gave no reason.`;
        setMessages((prev) => [
          ...prev,
          {
            id: `a-${prev.length}`,
            role: "assistant",
            content: detail,
            timestamp: now(),
            failed: true,
          },
        ]);
        return;
      }

      if (typeof data?.session_id === "string") setSessionId(data.session_id);
      setMessages((prev) => [
        ...prev,
        {
          id: `a-${prev.length}`,
          role: "assistant",
          content: String(data?.answer ?? "The service returned an empty answer."),
          timestamp: now(),
          evidence: Array.isArray(data?.evidence) ? data.evidence : [],
          recordsConsidered: Number(data?.records_considered ?? 0),
          aiUsed: !!data?.ai_used,
          model: data?.model ?? null,
          grounding: data?.grounding_status ?? null,
        },
      ]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setMessages((prev) => [
        ...prev,
        {
          id: `a-${prev.length}`,
          role: "assistant",
          content: `The request could not be sent: ${msg}`,
          timestamp: now(),
          failed: true,
        },
      ]);
    } finally {
      setSending(false);
    }
  };

  /* ── The service is not running ── */
  if (unreachable) {
    return (
      <div className="mx-auto max-w-3xl pt-10">
        <EmptyState
          icon={<ServerCrash className="h-9 w-9" />}
          title="Ask SENTRA is not running"
          detail="Start it with `uvicorn prototype_ai_chat.api:app --port 8100`. It needs DB_BACKEND=postgresql and the packages in prototype_ai_chat/requirements.txt. Nothing on this page answers from anything but the stored records, so it stays silent rather than guessing."
        />
      </div>
    );
  }

  return (
    <div className="mx-auto flex h-[calc(100vh-7rem)] max-w-[1200px] flex-col">
      <header className="flex shrink-0 flex-wrap items-start justify-between gap-4 px-1 pb-4">
        <div className="space-y-1.5">
          <p className="eyebrow">Ask SENTRA</p>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight text-ink">
            <Bot className="h-6 w-6 text-accent" />
            Question the incident record
          </h1>
          <p className="max-w-2xl text-xs leading-relaxed text-muted">
            Answers are retrieved from the stored incidents and campaigns, and every claim is checked
            against them before it is shown. Anything the records do not support is dropped.
          </p>
        </div>

        {messages.length > 0 ? (
          <button
            onClick={reset}
            className="inline-flex items-center gap-1.5 rounded-md border border-rule bg-surface px-3 py-1.5 text-xs font-medium text-muted transition-colors hover:bg-raised hover:text-ink"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            New conversation
          </button>
        ) : null}
      </header>

      {/* The service is up but cannot reach the records it would answer from. */}
      {noDatabase ? (
        <div className="mb-3 flex items-start gap-2.5 rounded-lg border border-sev-high/40 bg-sev-high/10 px-3 py-2.5">
          <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-sev-high" />
          <div className="space-y-0.5 text-xs">
            <p className="font-semibold text-ink">No incident store to answer from</p>
            <p className="text-muted">
              The service is running but its database is {health?.database ?? "unavailable"}.
              Retrieval requires <span className="mono">DB_BACKEND=postgresql</span>; the SQLite
              development fallback is deliberately disabled here. Questions are disabled rather than
              answered from nothing.
            </p>
          </div>
        </div>
      ) : null}

      {/* Up, with records, but no model — answers are deterministic, which is
          worth saying plainly rather than letting it read as a degraded model. */}
      {answerable && health?.gemini !== "available" ? (
        <div className="mb-3 flex items-start gap-2.5 rounded-lg border border-rule bg-surface px-3 py-2.5">
          <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
          <div className="space-y-0.5 text-xs">
            <p className="font-semibold text-ink">Answering without a language model</p>
            <p className="text-muted">
              No model is configured, so answers are assembled directly from the retrieved records.
              They are narrower and blunter, and they are still grounded. Set{" "}
              <span className="mono">GEMINI_API_KEY</span> to enable generation.
            </p>
          </div>
        </div>
      ) : null}

      <div className="flex flex-1 flex-col overflow-y-auto px-1 pb-4">
        {messages.length === 0 ? (
          <div className="my-auto flex flex-col items-center justify-center space-y-4 p-6 text-center">
            <div className="mb-2 inline-flex h-14 w-14 items-center justify-center rounded-2xl border border-accent/30 bg-accent/10 text-accent">
              <Sparkles className="h-7 w-7" />
            </div>

            <div className="max-w-2xl">
              <h2 className="mb-2 text-xl font-bold tracking-tight text-ink sm:text-2xl">
                What do you want to know about the incidents?
              </h2>
              <div className="flex min-h-[32px] items-center justify-center text-sm font-medium text-accent sm:text-base">
                <TextType
                  text={TYPED_LINES}
                  typingSpeed={45}
                  pauseDuration={2200}
                  deletingSpeed={25}
                  loop
                  showCursor
                  cursorCharacter="▋"
                  cursorClassName="text-accent ml-1"
                />
              </div>
            </div>

            <div className="grid w-full max-w-xl grid-cols-1 gap-2.5 pt-4 sm:grid-cols-2">
              {STARTERS.map((prompt) => (
                <button
                  key={prompt}
                  onClick={() => submit(prompt)}
                  disabled={!answerable || sending}
                  className="group flex items-center justify-between gap-2 rounded-lg border border-rule-soft bg-surface/60 p-2.5 text-left text-xs text-muted transition-all hover:border-accent-deep/60 hover:bg-surface hover:text-ink disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <span>{prompt}</span>
                  <Send className="h-3 w-3 shrink-0 text-faint transition-colors group-hover:text-accent" />
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {messages.map((msg, index) => {
              const isUser = msg.role === "user";
              const showAvatar =
                index === messages.length - 1 || messages[index + 1]?.role !== msg.role;

              return (
                <Message key={msg.id} align={isUser ? "end" : "start"}>
                  {showAvatar ? (
                    <MessageAvatar>
                      <Avatar>
                        <AvatarFallback
                          className={isUser ? "bg-accent text-sunk" : "bg-raised text-accent"}
                        >
                          {isUser ? "You" : <Bot className="h-4 w-4" />}
                        </AvatarFallback>
                      </Avatar>
                    </MessageAvatar>
                  ) : (
                    <div className="w-8" />
                  )}

                  <MessageContent>
                    <MessageHeader>{isUser ? "You" : "SENTRA"}</MessageHeader>
                    <Bubble variant={isUser ? "default" : "muted"}>
                      <BubbleContent>
                        <span className={msg.failed ? "text-sev-critical" : undefined}>
                          {msg.content}
                        </span>
                      </BubbleContent>
                    </Bubble>

                    {!isUser && !msg.failed ? <Provenance message={msg} /> : null}

                    <MessageFooter>{msg.timestamp}</MessageFooter>
                  </MessageContent>
                </Message>
              );
            })}

            {sending ? (
              <Message align="start">
                <MessageAvatar>
                  <Avatar>
                    <AvatarFallback className="bg-raised text-accent">
                      <Bot className="h-4 w-4" />
                    </AvatarFallback>
                  </Avatar>
                </MessageAvatar>
                <MessageContent>
                  <MessageHeader>SENTRA</MessageHeader>
                  <Bubble variant="muted">
                    <BubbleContent>
                      <span className="text-faint">Retrieving records…</span>
                    </BubbleContent>
                  </Bubble>
                </MessageContent>
              </Message>
            ) : null}

            <div ref={streamEnd} />
          </div>
        )}
      </div>

      <div className="shrink-0 border-t border-rule-soft bg-ground p-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit(input);
          }}
          className="relative mx-auto flex w-full max-w-4xl items-center rounded-lg border border-rule bg-surface p-1.5 transition-all focus-within:border-accent focus-within:ring-1 focus-within:ring-accent/40"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={!answerable || sending}
            aria-label="Ask a question about the stored incidents"
            placeholder={
              answerable
                ? "Ask about an incident, a campaign, a control, or a technique…"
                : "Unavailable until the service can reach the incident store"
            }
            className="flex-1 border-0 bg-transparent px-3 py-2 text-sm text-ink outline-none placeholder:text-faint disabled:cursor-not-allowed"
          />
          <button
            type="submit"
            disabled={!input.trim() || !answerable || sending}
            aria-label="Send"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent text-sunk transition hover:bg-accent-deep disabled:opacity-30 disabled:hover:bg-accent"
          >
            <Send className="h-3.5 w-3.5" />
          </button>
        </form>
      </div>
    </div>
  );
}

/**
 * What the answer above was based on.
 *
 * Without this an answer is just text on a screen, indistinguishable from one a
 * model invented. The counts and the citations are what make it checkable, so
 * they travel with the answer rather than sitting behind a toggle.
 */
function Provenance({ message }: { message: ChatMessage }) {
  const evidence = message.evidence ?? [];

  return (
    <div className="mt-1.5 space-y-1.5">
      {evidence.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-[0.14em] text-faint">From</span>
          {evidence.map((item) => {
            const href = evidenceHref(item);
            const label = `${item.type} ${item.id}`;
            return href ? (
              <Link
                key={`${item.type}-${item.id}`}
                href={href}
                className="mono rounded border border-rule bg-sunk px-1.5 py-0.5 text-[10px] text-muted transition-colors hover:border-accent-deep hover:text-accent"
              >
                {label}
              </Link>
            ) : (
              <span
                key={`${item.type}-${item.id}`}
                className="mono rounded border border-rule bg-sunk px-1.5 py-0.5 text-[10px] text-muted"
              >
                {label}
              </span>
            );
          })}
        </div>
      ) : null}

      <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] text-faint">
        <span>
          {message.recordsConsidered ?? 0}{" "}
          {message.recordsConsidered === 1 ? "record" : "records"} considered
        </span>
        <span aria-hidden>·</span>
        <span>
          {message.aiUsed ? `generated with ${message.model ?? "a model"}` : "assembled from records"}
        </span>
        {message.grounding ? (
          <>
            <span aria-hidden>·</span>
            <span className="mono">{message.grounding.replace(/_/g, " ")}</span>
          </>
        ) : null}
      </p>
    </div>
  );
}
