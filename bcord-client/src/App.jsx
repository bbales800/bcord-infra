import React, { useEffect, useRef, useState } from "react";

/**
 * BCord – minimal Discord-style chat skeleton
 * - Mints a short-lived WS token via /api/login
 * - Connects to wss://<host>/ws with user/channel/ts/token params
 * - Pings every 30s, auto-renews token ~every 4 min (server TTL = 5 min)
 */
export default function App() {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [status, setStatus] = useState("Connecting…");
  const wsRef = useRef(null);

  useEffect(() => {
    let ws;
    let alive = true;

    async function connect() {
      try {
        // 1) Mint a short-lived token from the backend
        const user = "dev";
        const channel = "general";
        const r = await fetch(
          `/api/login?user=${encodeURIComponent(user)}&channel=${encodeURIComponent(channel)}`
        );
        if (!r.ok) throw new Error(`login ${r.status}`);
        const { token, ts } = await r.json();

        // 2) Build WS URL with separate query params (Caddy will proxy)
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
          try {
            const data = JSON.parse(event.data);
            if (data?.op === "message" || data?.text) {
              setMessages((prev) => [...prev, data]);
            } else if (data?.op === "pong") {
              // no-op
            } else {
              // Echo (string) payload from server
              setMessages((prev) => [...prev, { text: event.data }]);
            }
          } catch {
            // Non-JSON payloads (echo path)
            setMessages((prev) => [...prev, { text: event.data }]);
          }
        };

        // 3) keepalive ping every 30s
        const pingId = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ op: "ping" }));
          }
        }, 30000);

        // 4) refresh token & reconnect before expiry (TTL=5m → refresh at ~4m)
        const refreshId = setTimeout(() => {
          try {
            ws && ws.close();
          } catch {}
          if (alive) connect(); // re-mint and reconnect
        }, 4 * 60 * 1000);

        // cleanup for this connect() call
        return () => {
          clearInterval(pingId);
          clearTimeout(refreshId);
          try {
            ws && ws.close();
          } catch {}
        };
      } catch (e) {
        setStatus("Error ⚠️");
        // backoff retry
        setTimeout(() => {
          if (alive) connect();
        }, 3000);
      }
    }

    const cleanup = connect();
    return () => {
      alive = false;
      cleanup && cleanup();
    };
  }, []);

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
          <div className="hover:bg-[#35373c] px-2 py-1 rounded cursor-pointer"># general</div>
          <div className="hover:bg-[#35373c] px-2 py-1 rounded cursor-pointer"># random</div>
        </div>
      </aside>

      {/* Chat Area */}
      <main className="flex-1 flex flex-col">
        <header className="px-4 py-2 border-b border-[#2b2d31] flex justify-between items-center font-semibold">
          <span># general</span>
          <span className="text-sm text-gray-400">{status}</span>
        </header>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {messages.length === 0 && (
            <div className="text-gray-500 text-sm">No messages yet...</div>
          )}
          {messages.map((m, i) => (
            <div key={i} className="bg-[#2b2d31] p-2 rounded break-words">
              {m.text || JSON.stringify(m)}
            </div>
          ))}
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

