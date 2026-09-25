import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import ErrorMessage from "../components/ErrorMessage.jsx";
import { askSecurityAssistant } from "../services/securityAssistant.js";
import { getApiError } from "../services/api.js";

const MAX_MESSAGE_LENGTH = 2000;

const SUGGESTIONS = [
  "What is happening in my environment in the last 24 hours?",
  "Show me my most recent high severity alerts",
  "Are there failed SSH logins from a single source IP?",
  "Which investigation notes mention a data exfiltration attempt?",
];

function newConversationId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return "00000000-0000-4000-8000-000000000000";
}

function formatTime(date) {
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

const SOURCE_ROUTES = {
  alert: (id) => `/alerts/${id}`,
  investigation: (id) => `/investigations/${id}`,
};

function SourceChip({ source }) {
  const label = `${source.type} #${source.id}`;
  const to = SOURCE_ROUTES[source.type]?.(source.id);
  if (!to) {
    return <span className="badge badge-source">{label}</span>;
  }
  return (
    <Link className="badge badge-source badge-source-link" to={to}>
      {label}
    </Link>
  );
}

export default function SecurityAssistant() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");
  const conversationIdRef = useRef(newConversationId());
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages, sending]);

  const send = async (text) => {
    const trimmed = text.trim();
    if (!trimmed || sending) return;

    setError("");
    setInput("");
    setSending(true);
    setMessages((current) => [
      ...current,
      { id: `ask-${current.length}`, role: "user", text: trimmed },
    ]);

    try {
      const data = await askSecurityAssistant(trimmed, conversationIdRef.current);
      if (data?.conversation_id) {
        conversationIdRef.current = data.conversation_id;
      }
      setMessages((current) => [
        ...current,
        {
          id: `answer-${current.length}`,
          role: "assistant",
          text: data?.message || "",
          sources: Array.isArray(data?.sources) ? data.sources : [],
        },
      ]);
    } catch (err) {
      setError(getApiError(err));
    } finally {
      setSending(false);
    }
  };

  const startNewConversation = () => {
    conversationIdRef.current = newConversationId();
    setMessages([]);
    setError("");
  };

  const disabled = sending || !input.trim();

  return (
    <div className="page-pad assistant-page">
      <div className="page-head">
        <div>
          <h2 className="page-title">Security Assistant</h2>
          <p className="page-subtitle">
            Ask questions about your own events, alerts, investigations and detection rules.
            Answers are generated from your data only and every request is audited.
          </p>
        </div>
        <div className="toolbar">
          <button
            className="btn btn-outline btn-sm"
            onClick={startNewConversation}
            disabled={sending || messages.length === 0}
          >
            New conversation
          </button>
        </div>
      </div>

      <div className="card assistant-card">
        <div className="assistant-log" aria-live="polite">
          {messages.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">◈</div>
              <h4>Ask about your security data</h4>
              <p>
                The assistant can only read records that belong to your account. It cannot change
                anything, and it will say so when your data does not answer a question.
              </p>
            </div>
          )}

          {messages.map((message) => (
            <div key={message.id} className={`chat-row ${message.role}`}>
              <div className="chat-meta">
                <span>{message.role === "user" ? "You" : "Assistant"}</span>
                <span className="chat-time">{formatTime(new Date())}</span>
              </div>
              <div className="chat-bubble">
                {message.text}
                {message.sources?.length > 0 && (
                  <div className="chat-sources">
                    <span className="chat-sources-label">Sources</span>
                    {message.sources.slice(0, 8).map((source) => (
                      <SourceChip key={`${source.type}-${source.id}`} source={source} />
                    ))}
                    {message.sources.length > 8 && (
                      <span className="dim-cell">+{message.sources.length - 8} more</span>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}

          {sending && (
            <div className="chat-row assistant">
              <div className="chat-meta">
                <span>Assistant</span>
              </div>
              <div className="chat-bubble chat-bubble-pending">Analysing your data…</div>
            </div>
          )}

          <div ref={endRef} />
        </div>

        {error && <ErrorMessage message={error} />}

        {messages.length === 0 && (
          <div className="assistant-suggestions">
            {SUGGESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                className="btn btn-outline btn-sm"
                onClick={() => send(suggestion)}
                disabled={sending}
              >
                {suggestion}
              </button>
            ))}
          </div>
        )}

        <form
          className="assistant-composer"
          onSubmit={(event) => {
            event.preventDefault();
            send(input);
          }}
        >
          <label className="field assistant-input">
            <span className="field-label">Your question</span>
            <textarea
              rows={2}
              value={input}
              maxLength={MAX_MESSAGE_LENGTH}
              placeholder="What changed in my alert volume today?"
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  send(input);
                }
              }}
              disabled={sending}
            />
          </label>
          <div className="assistant-composer-meta">
            <span className="dim-cell">
              {input.length}/{MAX_MESSAGE_LENGTH} · Enter to send, Shift+Enter for a new line
            </span>
            <button type="submit" className="btn btn-primary" disabled={disabled}>
              {sending ? "Asking…" : "Ask"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
