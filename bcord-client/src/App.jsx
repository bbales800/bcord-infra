//============================================================================
// BCord Frontend — React Client (v1.2.0-Rumble Secure + OpenCaptcha)
// ----------------------------------------------------------------------------
// ✅ Login / Register / Verify screens added
// ✅ Uses /api/register and /api/verify endpoints
// ✅ Keeps localStorage username for chat identity
// ✅ Shows timestamps under message text
// ✅ Integrates self-hosted OpenCaptcha
// ✅ CAPTCHA reloads dynamically
// ✅ Uses /api/register and /api/verify endpoints
// ============================================================================

import React, { useState } from "react";
import { RegisterForm } from "./components/RegisterForm";
import { VerifyForm } from "./components/VerifyForm";
import { LoginForm } from "./components/LoginForm";

export default function App() {
  const [view, setView] = useState("register");

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", maxWidth: 480, margin: "40px auto" }}>
      <h2>BCord Authentication</h2>
      <nav style={{ display: "flex", gap: 8 }}>
        <button onClick={() => setView("register")}>Register</button>
        <button onClick={() => setView("verify")}>Verify</button>
        <button onClick={() => setView("login")}>Login</button>
      </nav>
      <hr />
      {view === "register" && <RegisterForm />}
      {view === "verify" && <VerifyForm />}
      {view === "login" && <LoginForm />}
    </div>
  );
}


// ---------------------------------------------------------------------------
// Helper: timestamp formatting
// ---------------------------------------------------------------------------
function fmt(ts) {
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Authentication Form with CAPTCHA
// ---------------------------------------------------------------------------
function AuthPanel({ onAuthComplete }) {
  const [mode, setMode] = useState("login"); // login | register | verify
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [status, setStatus] = useState("");

  // CAPTCHA states
  const [captchaImage, setCaptchaImage] = useState(null);
  const [captchaText, setCaptchaText] = useState("");
  const [captchaInput, setCaptchaInput] = useState("");

  // Load CAPTCHA from your local OpenCaptcha container
  async function loadCaptcha() {
    try {
      const text = Math.random().toString(36).substring(2, 8).toUpperCase();
      const res = await fetch("http://localhost:5280/captcha", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          width: 400,
          height: 100,
          difficulty: 2,
        }),
      });
      const blob = await res.blob();
      setCaptchaText(text);
      setCaptchaImage(URL.createObjectURL(blob));
    } catch {
      setStatus("⚠️ Failed to load CAPTCHA");
    }
  }

  useEffect(() => {
    if (mode === "register") loadCaptcha();
  }, [mode]);

  // -------------------------------------------------------------------------
  // Handle Registration
  // -------------------------------------------------------------------------
  async function handleRegister() {
    try {
      if (captchaInput.trim().toUpperCase() !== captchaText.trim().toUpperCase()) {
        setStatus("❌ CAPTCHA does not match. Try again.");
        loadCaptcha();
        return;
      }

      setStatus("Creating account...");
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password,
          email,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Registration failed");
      setStatus(data.message);
      setMode("verify");
    } catch (err) {
      setStatus(err.message);
    }
  }

  // -------------------------------------------------------------------------
  // Handle Verification and Login
  // -------------------------------------------------------------------------
  async function handleVerify() {
    try {
      setStatus("Verifying...");
      const res = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, code }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Verification failed");
      localStorage.setItem("username", username);
      setStatus("✅ Verified! Logging in...");
      onAuthComplete(username);
    } catch (err) {
      setStatus(err.message);
    }
  }

  async function handleLogin() {
    try {
      setStatus("Logging in...");
      localStorage.setItem("username", username);
      onAuthComplete(username);
    } catch (err) {
      setStatus(err.message);
    }
  }
  // -------------------------------------------------------------------------
  // Render Auth Modes
  // -------------------------------------------------------------------------
  return (
    <div className="h-screen flex items-center justify-center bg-[#1e1f22] text-white">
      <div className="w-80 bg-[#2b2d31] rounded-xl p-6 shadow-lg space-y-4 text-center">
        <h1 className="text-2xl font-bold">BCord</h1>

        {/* LOGIN MODE */}
        {mode === "login" && (
          <>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              className="w-full bg-[#383a40] rounded p-2 outline-none mb-2"
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              className="w-full bg-[#383a40] rounded p-2 outline-none mb-2"
            />
            <button
              onClick={handleLogin}
              className="w-full bg-[#5865f2] hover:bg-[#4752c4] py-2 rounded"
            >
              Login
            </button>
            <button
              onClick={() => setMode("register")}
              className="text-sm text-gray-400 underline"
            >
              Create Account
            </button>
          </>
        )}

        {/* REGISTER MODE (with CAPTCHA) */}
        {mode === "register" && (
          <>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              className="w-full bg-[#383a40] rounded p-2 outline-none mb-2"
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              className="w-full bg-[#383a40] rounded p-2 outline-none mb-2"
            />
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Email"
              className="w-full bg-[#383a40] rounded p-2 outline-none mb-2"
            />
            {/* CAPTCHA SECTION */}
            <div className="my-2">
              {captchaImage ? (
                <img src={captchaImage} alt="CAPTCHA" className="w-full rounded mb-2" />
              ) : (
                <div className="text-gray-400 text-sm mb-2">Loading CAPTCHA...</div>
              )}
              <input
                value={captchaInput}
                onChange={(e) => setCaptchaInput(e.target.value)}
                placeholder="Enter CAPTCHA"
                className="w-full bg-[#383a40] rounded p-2 outline-none mb-2"
              />
              <button
                onClick={loadCaptcha}
                className="bg-gray-600 hover:bg-gray-500 px-3 py-1 rounded text-sm"
              >
                Reload CAPTCHA
              </button>
            </div>

            <button
              onClick={handleRegister}
              className="w-full bg-green-600 hover:bg-green-500 py-2 rounded"
            >
              Register
            </button>
            <button
              onClick={() => setMode("login")}
              className="text-sm text-gray-400 underline"
            >
              Back to Login
            </button>
          </>
        )}

        {/* VERIFY MODE */}
        {mode === "verify" && (
          <>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Verification Code"
              className="w-full bg-[#383a40] rounded p-2 outline-none mb-2"
            />
            <button
              onClick={handleVerify}
              className="w-full bg-[#5865f2] hover:bg-[#4752c4] py-2 rounded"
            >
              Verify Email
            </button>
          </>
        )}

        {status && <div className="text-sm text-gray-400 mt-2">{status}</div>}
      </div>
    </div>
  );
}

