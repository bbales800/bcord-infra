import React, { useState } from "react";

export default function App() {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");

  const handleSend = () => {
    if (!text.trim()) return;
    setMessages([...messages, { id: Date.now(), text }]);
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

      {/* Chat */}
      <main className="flex-1 flex flex-col">
        <header className="px-4 py-2 border-b border-[#2b2d31] font-semibold">
          # general
        </header>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {messages.map((m) => (
            <div key={m.id} className="bg-[#2b2d31] p-2 rounded">
              {m.text}
            </div>
          ))}
        </div>

        {/* Input */}
        <div className="p-4 border-t border-[#2b2d31]">
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            placeholder="Type a message..."
            className="w-full bg-[#383a40] text-white rounded p-2 outline-none"
          />
        </div>
      </main>
    </div>
  );
}

