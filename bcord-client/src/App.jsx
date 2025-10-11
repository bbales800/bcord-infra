import React, { useEffect, useRef, useState } from "react";

function fmt(ts) {
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return "";
  }
}

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
  const [status, setStatus] = useState("Connecting…");
  const [channel, setChannel] = useState("general");
  const [username, setUsername] = useState(
    () => localStorage.getItem("username") || "guest"
  );
  const wsRef = useRef(null);
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function loadHistory(ch) {
    try {
      const r = await fetch(`/api/history?channel=${encodeURIComponent(ch)}&limit=50`);
      if (!r.ok) throw new Error(`history ${r.status}`);
      const rows = await r.json();
      const ordered = rows
        .slice()
        .reverse()
        .map((m) => ({
          id: m.id,
          text: m.body,
          ts: m.created_at,
          sender: m.sender || "unknown",
        }));
      setMessages(ordered);
    } catch (e) {
      console.error(e);
    }
  }

  // Safe reconnecting WebSocket logic
  useEffect(() => {
    let ws;
    let alive = true;
    let cleanupFns = [];

    async function connect() {
      try {
        await loadHistory(channel);

        const user = username || "guest";
        setStatus(`Connecting as ${user}…`);

        const r = await fetch(`/api/login?channel=${encodeURIComponent(channel)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: user }),
        });
        if (!r.ok) throw new Error(`login ${r.status}`);
        const { token, ts } = await r.json();

        const host = window.location.host;
        const wsUrl = `wss://${host}/ws?user=${encodeURIComponent(
          user
        )}&channel=${encodeURIComponent(channel)}&ts=${ts}&token=${token}`;

        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => alive && setStatus(`Connected ✅ as ${user}`);
        ws.onclose = () => alive && setStatus("Reconnecting…");
        ws.onerror = () => alive && setStatus("Error ⚠️");

        ws.onmessage = (event) => {
          if (event.data === '{"op":"pong"}') return;
          try {
            const data = JSON.parse(event.data);
            if (data && (data.op === "message" || data.text)) {
              const ts = data.ts || new Date().toISOString();
              const sender = data.sender || "unknown";
              const textPayload = data.text ?? data.body ?? "";
              setMessages((prev) => [...prev, { text: textPayload, ts, sender }]);
              return;
            }
          } catch {
            setMessages((prev) => [
              ...prev,
              { text: event.data, ts: new Date().toISOString(), sender: "unknown" },
            ]);
          }
        };

        const pingId = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN)
            ws.send(JSON.stringify({ op: "ping" }));
        }, 30000);

        const refreshId = setTimeout(() => {
          try {
            ws && ws.close();
          } catch {}
          if (alive) connect();
        }, 4 * 60 * 1000);

        cleanupFns.push(() => {
          clearInterval(pingId);
          clearTimeout(refreshId);
          ws.close();
        });
      } catch (e) {
        console.error(e);
        setStatus("Error ⚠️");
        setTimeout(() => alive && connect(), 3000);
      }
    }

    connect();

    return () => {
      alive = false;
      cleanupFns.forEach((fn) => fn && fn());
    };
  }, [channel, username]); // reconnect only, no blanking messages

  const sendMessage = () => {
    const trimmed = text.trim();
    if (!trimmed || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify({ op: "message", text: trimmed }));
    setText("");
  };

  return (
    <div className="h-screen flex text-gray-100 bg-[#1e1f22]">
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

      <main className="flex-1 flex flex-col">
        <header className="px-4 py-2 border-b border-[#2b2d31] flex flex-col gap-2 md:flex-row md:items-center md:justify-between md:gap-4 font-semibold">
          <span>#{channel}</span>
          <div className="flex flex-col gap-2 md:flex-row md:items-center md:gap-4">
            <UsernameBar username={username} onChange={setUsername} />
            <span className="text-sm text-gray-400 md:self-center">{status}</span>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {messages.length === 0 && (
            <div className="text-gray-500 text-sm">No messages yet...</div>
          )}
          {messages.map((m, i) => (
            <div key={i} className="bg-[#2b2d31] p-2 rounded break-words">
              <div className="text-xs text-gray-400">{fmt(m.ts)}</div>
              <div>
                <strong className="text-gray-200">{m.sender || "unknown"} – </strong>
                {m.text}
              </div>
            </div>
          ))}
          <div ref={endRef} />
        </div>

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

