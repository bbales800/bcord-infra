import React, { useEffect, useRef, useState } from "react";

function fmt(ts) {
  // Expect ISO string from API; fallback to current time if missing
  try { return new Date(ts).toLocaleTimeString(); } catch { return ""; }
}

export default function App() {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [status, setStatus] = useState("Connecting…");
  const [channel, setChannel] = useState("general"); // active channel
  const wsRef = useRef(null);
  const endRef = useRef(null);

  // auto-scroll when messages change
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // load history for active channel
  async function loadHistory(ch) {
    try {
      const r = await fetch(`/api/history?channel=${encodeURIComponent(ch)}&limit=50`);
      if (!r.ok) throw new Error(`history ${r.status}`);
      const rows = await r.json(); // [{id,sender,body,created_at,deleted,edited}]
      // Most recent first from your SQL — flip to ascending for chat view
      const ordered = rows.slice().reverse().map((m) => ({
        id: m.id,
        text: m.body,
        ts: m.created_at,
        sender: m.sender,
        deleted: m.deleted,
        edited: m.edited,
      }));
      setMessages(ordered);
    } catch (e) {
      console.error(e);
    }
  }

  // connect WS for active channel
  useEffect(() => {
    let ws;
    let alive = true;

    async function connect() {
      try {
        // (re)load history for the channel
        await loadHistory(channel);

        // mint short-lived token
        const user = "dev"; // keep static for now; we’ll add a username prompt later
        const r = await fetch(
          `/api/login?user=${encodeURIComponent(user)}&channel=${encodeURIComponent(channel)}`
        );
        if (!r.ok) throw new Error(`login ${r.status}`);
        const { token, ts } = await r.json();

        // build WS URL (Caddy will proxy)
        const host = window.location.host;
        const wsUrl = `wss://${host}/ws?user=${encodeURIComponent(
          user
        )}&channel=${encodeURIComponent(channel)}&ts=${ts}&token=${token}`;

        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => alive && setStatus("Connected ✅");
        ws.onclose = () => alive && setStatus("Disconnected ❌");
        ws.onerror = () => alive && setStatus("Error ⚠️");

        ws.onmessage = (event) => {
          // Hide pongs
          if (event.data === '{"op":"pong"}') return;

          try {
            const data = JSON.parse(event.data);
            if (data && typeof data === "object" && "text" in data) {
              setMessages((prev) => [...prev, { text: data.text, ts: new Date().toISOString(), sender: "me" }]);
            }
          } catch {
            // Plain echo path: show as text line
            setMessages((prev) => [...prev, { text: event.data, ts: new Date().toISOString() }]);
          }
        };

        // keepalive ping every 30s
        const pingId = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ op: "ping" }));
          }
        }, 30000);

        // refresh token before it expires (~5m TTL → refresh ~4m)
        const refreshId = setTimeout(() => {
          try { ws && ws.close(); } catch {}
          if (alive) connect();
        }, 4 * 60 * 1000);

        return () => {
          clearInterval(pingId);
          clearTimeout(refreshId);
          try { ws && ws.close(); } catch {}
        };
      } catch (e) {
        console.error(e);
        setStatus("Error ⚠️");
        setTimeout(() => { if (alive) connect(); }, 3000);
      }
    }

    const cleanup = connect();
    return () => { alive = false; cleanup && cleanup(); };
  }, [channel]);

  const sendMessage = () => {
    const trimmed = text.trim();
    if (!trimmed || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    const msg = { op: "message", text: trimmed };
    wsRef.current.send(JSON.stringify(msg));
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

      {/* Chat Area */}
      <main className="flex-1 flex flex-col">
        <header className="px-4 py-2 border-b border-[#2b2d31] flex justify-between items-center font-semibold">
          <span>#{channel}</span>
          <span className="text-sm text-gray-400">{status}</span>
        </header>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {messages.length === 0 && (
            <div className="text-gray-500 text-sm">No messages yet...</div>
          )}
          {messages.map((m, i) => (
            <div key={i} className="bg-[#2b2d31] p-2 rounded break-words">
              <div className="text-xs text-gray-400">{fmt(m.ts)}</div>
              <div>{m.text || JSON.stringify(m)}</div>
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

