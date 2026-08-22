(() => {
  "use strict";

  const MAX_LENGTH = 2000;
  const form = document.querySelector("#chat-form");
  const input = document.querySelector("#message");
  const send = document.querySelector("#send");
  const conversation = document.querySelector("#conversation");
  const loading = document.querySelector("#loading");
  const counter = document.querySelector("#counter");
  const health = document.querySelector("#health");
  const reset = document.querySelector("#new-conversation");
  let sessionId = null;
  let busy = false;

  function setBusy(value) {
    busy = value;
    send.disabled = value;
    input.disabled = value;
    loading.hidden = !value;
  }

  function appendInlineMarkdown(container, text) {
    // Text nodes escape HTML by construction. Only this small allowlist of
    // formatting elements can be created from an assistant response.
    const pattern = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\*[^*\n]+\*)/g;
    let offset = 0;
    for (const match of String(text).matchAll(pattern)) {
      if (match.index > offset) container.append(document.createTextNode(text.slice(offset, match.index)));
      const token = match[0];
      const element = document.createElement(token.startsWith("`") ? "code" : token.startsWith("**") ? "strong" : "em");
      element.textContent = token.startsWith("**") ? token.slice(2, -2) : token.slice(1, -1);
      container.append(element);
      offset = match.index + token.length;
    }
    if (offset < text.length) container.append(document.createTextNode(text.slice(offset)));
  }

  function addParagraphs(container, text) {
    const lines = String(text).split(/\r?\n/);
    let list = null;
    let listType = null;
    lines.forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed) {
        list = null;
        listType = null;
        return;
      }
      const heading = trimmed.match(/^(#{1,6})\s+(.+)$/);
      if (heading) {
        list = null;
        listType = null;
        const title = document.createElement(`h${heading[1].length}`);
        appendInlineMarkdown(title, heading[2]);
        container.append(title);
        return;
      }
      const unordered = trimmed.match(/^[-*]\s+(.+)$/);
      const ordered = trimmed.match(/^\d+[.)]\s+(.+)$/);
      if (unordered || ordered) {
        const type = ordered ? "ol" : "ul";
        if (!list || listType !== type) {
          list = document.createElement(type);
          listType = type;
          container.append(list);
        }
        const item = document.createElement("li");
        appendInlineMarkdown(item, (ordered || unordered)[1]);
        list.append(item);
      } else {
        list = null;
        listType = null;
        const paragraph = document.createElement("p");
        appendInlineMarkdown(paragraph, trimmed);
        container.append(paragraph);
      }
    });
  }

  function addMessage(role, text, data = null, isError = false) {
    const welcome = conversation.querySelector(".welcome");
    if (welcome) welcome.remove();
    const article = document.createElement("article");
    article.className = `message ${role}${isError ? " error-message" : ""}`;
    const speaker = document.createElement("p");
    speaker.className = "speaker";
    speaker.textContent = role === "user" ? "You" : "SENTRA AI";
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    addParagraphs(bubble, text);
    article.append(speaker, bubble);

    if (data) {
      const meta = document.createElement("div");
      meta.className = "meta";
      const mode = document.createElement("span");
      mode.className = `tag${data.ai_used ? " ai" : ""}`;
      const deterministicLabels = {
        greeting: "Greeting",
        capabilities: "Capabilities",
        out_of_scope: "Scope boundary",
      };
      mode.textContent = deterministicLabels[data.intent] ||
        (data.grounding_status === "verified" ? "Verified against SENTRA evidence" :
          data.grounding_status === "general_knowledge" ? "General cybersecurity knowledge" :
            data.grounding_status === "deterministic" ? "Deterministic evidence response" :
              data.intent === "general_security" && data.ai_used ? "General security explanation" :
                data.ai_used ? "Gemini analysis" : "Deterministic fallback");
      const intent = document.createElement("span");
      intent.className = "tag";
      intent.textContent = `Intent: ${data.intent}`;
      meta.append(mode, intent);
      article.append(meta);

      if (Array.isArray(data.evidence) && data.evidence.length) {
        const details = document.createElement("details");
        details.className = "evidence";
        const summary = document.createElement("summary");
        summary.textContent = `Evidence (${data.evidence.length})`;
        const badges = document.createElement("div");
        badges.className = "badges";
        data.evidence.forEach((evidence) => {
          const badge = document.createElement("span");
          badge.className = "badge";
          const label = evidence.type === "mitre_technique" ? "MITRE" :
            evidence.type === "control" ? "Control" :
            evidence.type.charAt(0).toUpperCase() + evidence.type.slice(1);
          badge.textContent = `${label}: ${evidence.id}`;
          badges.append(badge);
        });
        details.append(summary, badges);
        article.append(details);
      }
    }
    conversation.append(article);
    conversation.scrollTop = conversation.scrollHeight;
  }

  async function sendMessage(text) {
    const message = text.trim();
    if (!message || busy || message.length > MAX_LENGTH) return;
    addMessage("user", message);
    input.value = "";
    counter.textContent = `0 / ${MAX_LENGTH}`;
    setBusy(true);
    try {
      const payload = { message };
      if (sessionId) payload.session_id = sessionId;
      const response = await fetch("/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const message = response.status === 422 ? "Please enter a valid question under 2,000 characters." :
          response.status === 503 ? "The security database is currently unavailable." :
          "SENTRA could not complete that request. Please try again.";
        throw new Error(message);
      }
      const data = await response.json();
      sessionId = data.session_id;
      addMessage("assistant", data.answer, data);
    } catch (error) {
      const allowed = new Set([
        "Please enter a valid question under 2,000 characters.",
        "The security database is currently unavailable.",
        "SENTRA could not complete that request. Please try again.",
      ]);
      const safeMessage = allowed.has(error.message) ? error.message :
        "The chatbot service is unavailable. Please try again.";
      addMessage("assistant", safeMessage, null, true);
    } finally {
      setBusy(false);
      input.focus();
    }
  }

  async function checkHealth() {
    try {
      const response = await fetch("/health");
      if (!response.ok) throw new Error();
      const data = await response.json();
      health.className = data.database === "connected" ? "status ready" : "status error";
      health.lastChild.textContent = data.database !== "connected" ? "Database unavailable" :
        data.gemini === "available" ? "System ready" : "System ready — AI fallback mode";
    } catch {
      health.className = "status error";
      health.lastChild.textContent = "System unavailable";
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    sendMessage(input.value);
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      form.requestSubmit();
    }
  });
  input.addEventListener("input", () => {
    counter.textContent = `${input.value.length} / ${MAX_LENGTH}`;
    send.disabled = busy || !input.value.trim();
  });
  document.querySelectorAll("[data-question]").forEach((button) => {
    button.addEventListener("click", () => sendMessage(button.dataset.question));
  });
  reset.addEventListener("click", async () => {
    const previous = sessionId;
    sessionId = null;
    if (previous) {
      try { await fetch(`/sessions/${encodeURIComponent(previous)}`, { method: "DELETE" }); } catch { /* local reset still succeeds */ }
    }
    conversation.replaceChildren();
    const welcome = document.createElement("article");
    welcome.className = "welcome";
    const mark = document.createElement("div");
    mark.className = "mark";
    mark.textContent = "S";
    const copy = document.createElement("div");
    const title = document.createElement("h2");
    title.textContent = "New conversation";
    const note = document.createElement("p");
    note.textContent = "Your previous local session was cleared. Ask a new security question when ready.";
    copy.append(title, note);
    welcome.append(mark, copy);
    conversation.append(welcome);
    input.focus();
  });

  send.disabled = true;
  checkHealth();
})();
