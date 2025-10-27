// ============================================================================
// BCord Frontend — React Client (v1.0.5-Rumble)
// ----------------------------------------------------------------------------
// ✅ Dynamic WebSocket URL uses current host (no hard-coded domain)
// ✅ Displays backend Online/Offline status
// ✅ Keyboard "Enter" sends messages instantly
// ✅ Ignores ping messages from server
// ✅ Shows username correctly from localStorage
// ✅ Timestamp displayed under message text
// ============================================================================

import React, { useEffect, useRef, useState } from "react";

// ---------------------------------------------------------------------------
// Helper: timestamp formatting
// ---------------------------------------------------------------------------
function fmt(ts) {
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return "";
  }
}// ---------------------------------------------------------------------------
// Component: UsernameBar
// • Stores username in localStorage
// • Triggers reconnect when changed
// ---------------------------------------------------------------------------
function UsernameBar({ username, onChange }) {
  const [draft, setDraft] = useState(username);
  useEffect(() => setDraft(username), [username]);

  const persist = () => {
    const next = draft.trim() || "guest";
    localStorage.setItem("username", next);
    onChange(next);
  };

  return (
    <div className="flex items-center gap-2 text-sm">
      <input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && persist()}
        placeholder="Enter username"
        className="bg-[#383a40] text-white rounded px-2 py-1 outline-none border border-transparent focus:border-[#5865f2]"
      />
      <button
        onClick={persist}
        className="bg-[#5865f2] hover:bg-[#4752c4] text-white px-3 py-1 rounded"
      >
        Save
      </button>
    </div>
  );
}
export default function App() {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [status, setStatus] = useState("Checking backend...");
  const [channel, setChannel] = useState("general");
  const [username, setUsername] = useState(
    () => localStorage.getItem("username") || "guest"
  );

  const wsRef = useRef(null);
  const endRef = useRef(null);

  // Auto-scroll on new messages
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);
  async function loadHistory(ch) {
    try {
      const res = await fetch(`/api/history?channel=${encodeURIComponent(ch)}&limit=50`);
      if (!res.ok) throw new Error(`history ${res.status}`);
      const data = await res.json();

      const rows = Array.isArray(data)
        ? data
        : Array.isArray(data.rows)
        ? data.rows
        : [];

      const ordered = rows
        .filter((m) => typeof m === "object" && m !== null)
        .slice()
        .reverse()
        .map((m) => ({
          text: m.text ?? "",
          ts: m.ts ?? new Date().toISOString(),
          sender: m.sender || "unknown",
        }));

      setMessages(ordered);
      setStatus("✅ Backend Online");
    } catch (err) {
      console.error("History load error:", err);
      setStatus("⚠️ Backend Offline");
    }
  }
  useEffect(() => {
    let ws;
    let alive = true;
    const cleanup = [];

    async function connect() {
      try {
        await loadHistory(channel);
        const user = username || "guest";
        setStatus(`Connecting as ${user}...`);

        const loginRes = await fetch(`/api/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: user }),
        });
        if (!loginRes.ok) throw new Error(`login ${loginRes.status}`);
        const { token = "demo-token" } = await loginRes.json();

        const host = window.location.host;
        const wsUrl = `wss://${host}/ws?user=${encodeURIComponent(
          user
        )}&channel=${encodeURIComponent(channel)}&token=${token}`;

        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => alive && setStatus("✅ Connected");
        ws.onclose = () => alive && setStatus("Reconnecting...");
        ws.onerror = () => alive && setStatus("⚠️ WebSocket Error");

        // Handle messages
        ws.onmessage = (event) => {
          if (!event.data) return;
          try {
            const data = JSON.parse(event.data);
            // Ignore pings and empty text
            if (data.op === "ping" || !data.text) return;

            const msg = {
              text: data.text,
              ts: data.ts ? new Date(data.ts * 1000).toISOString() : new Date().toISOString(),
              sender: data.user || "unknown",
              channel: data.channel || "general",
            };
            setMessages((prev) => [...prev, msg]);
          } catch (err) {
            console.error("WS parse error:", err);
          }
        };

        const pingId = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN)
            ws.send(JSON.stringify({ op: "ping" }));
        }, 25000);

        const refreshId = setTimeout(() => {
          try {
            ws && ws.close();
          } catch {}
          if (alive) connect();
        }, 4 * 60 * 1000);

        cleanup.push(() => {
          clearInterval(pingId);
          clearTimeout(refreshId);
          ws.close();
        });
      } catch (err) {
        console.error("WS connect error:", err);
        setStatus("⚠️ Backend Offline");
        setTimeout(() => alive && connect(), 4000);
      }
    }

    connect();
    return () => {
      alive = false;
      cleanup.forEach((fn) => fn && fn());
    };
  }, [channel, username]);
  const sendMessage = () => {
    const trimmed = text.trim();
    if (!trimmed || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;

    const payload = JSON.stringify({
      user: username,
      channel,
      text: trimmed,
    });

    wsRef.current.send(payload);
    setText("");
  };
  return (
    <div className="h-screen flex text-gray-100 bg-[#1e1f22]">
      {/* Sidebar */}
      <aside className="w-64 bg-[#2b2d31] flex flex-col">
        <div className="px-4 py-3 text-lg font-bold border-b border-[#1e1f22]">BCord</div>
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {["general", "random"].map((ch) => (
            <button
              key={ch}
              onClick={() => setChannel(ch)}
              className={`w-full text-left px-2 py-1 rounded cursor-pointer ${
                channel === ch ? "bg-[#404249]" : "hover:bg-[#35373c]"
              }`}
            >
              #{ch}
            </button>
          ))}
        </div>
      </aside>

      {/* Main Chat */}
      <main className="flex-1 flex flex-col">
        <header className="px-4 py-2 border-b border-[#2b2d31] flex flex-col md:flex-row md:justify-between md:items-center gap-2 font-semibold">
          <span>#{channel}</span>
          <div className="flex flex-col md:flex-row md:items-center gap-4">
            <UsernameBar username={username} onChange={setUsername} />
            <span className="text-sm text-gray-400">{status}</span>
            <span className="text-xs text-gray-500">v1.0.5</span>
          </div>
        </header>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {Array.isArray(messages) && messages.length === 0 && (
            <div className="text-gray-500 text-sm">No messages yet...</div>
          )}
          {Array.isArray(messages) &&
            messages.map((m, i) => (
              <div key={i} className="bg-[#2b2d31] p-2 rounded break-words">
                <div>
                  <strong className="text-gray-200">{m.sender}</strong> – {m.text}
                </div>
                <div className="text-xs text-gray-400 mt-1">{fmt(m.ts)}</div>
              </div>
            ))}
          <div ref={endRef} />
        </div>

        {/* Input */}
        <div className="p-4 border-t border-[#2b2d31]">
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && sendMessage()}
            placeholder="Type a message..."
            className="w-full bg-[#383a40] text-white rounded p-2 outline-none"
          />
        </div>
      </main>
    </div>
  );
}

