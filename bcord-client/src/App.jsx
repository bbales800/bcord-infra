import React, { useEffect, useState, useRef } from "react";

export default function App() {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [status, setStatus] = useState("Connecting...");
  const wsRef = useRef(null);

  // Connect to BCord backend WebSocket
  useEffect(() => {
     const tokenParam = "?token=dev";
     const wsUrl =
       import.meta.env.VITE_WS_URL
         ? `${import.meta.env.VITE_WS_URL}${tokenParam}`
         : `wss://www.b-cord.run.place/ws${tokenParam}`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => setStatus("Connected ✅");
    ws.onclose = () => setStatus("Disconnected ❌");
    ws.onerror = () => setStatus("Error ⚠️");

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data?.op === "message" || data?.text) {
          setMessages((prev) => [...prev, data]);
        } else if (data?.op === "pong") {
          console.log("Received pong");
        } else {
          console.log("Other message:", data);
        }
      } catch {
        console.log("Non-JSON message:", event.data);
      }
    };

    // Ping every 30 seconds to keep alive
    const interval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN)
        ws.send(JSON.stringify({ op: "ping" }));
    }, 30000);

    return () => {
      clearInterval(interval);
      ws.close();
    };
  }, []);

  const sendMessage = () => {
    const trimmed = text.trim();
    if (!trimmed || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN)
      return;
    const msg = { op: "message", text: trimmed };
    wsRef.current.send(JSON.stringify(msg));
    setText("");
  };

  return (
    <div className="h-screen flex text-gray-100 bg-[#1e1f22]">
      {/* Sidebar */}
      <aside className="w-64 bg-[#2b2d31] flex flex-col">
        <div className="px-4 py-3 text-lg font-bold border-b border-[#1e1f22]">
          BCord
        </div>
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          <div className="hover:bg-[#35373c] px-2 py-1 rounded cursor-pointer">
            # general
          </div>
          <div className="hover:bg-[#35373c] px-2 py-1 rounded cursor-pointer">
            # random
          </div>
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

