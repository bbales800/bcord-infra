//============================================================================
// BCord Frontend — Authentication Flow
// ----------------------------------------------------------------------------
// • Presents a login-first experience with contextual routing to registration
// • Registration bundles CAPTCHA verification and email code confirmation
// • Supports OpenCaptcha proxy at /captcha with client-side refresh handling
// • Guides the user back to the login screen (or new tab) after verification
// • Successful login redirects visitors to the primary chat landing page
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { login, register, verify } from "./api";
import useTokenRefresher from "./hooks/useTokenRefresher";

const CARD_STYLE = {
  width: "100%",
  maxWidth: 420,
  margin: "0 auto",
  background: "#ffffff",
  borderRadius: 16,
  padding: "32px 28px",
  boxShadow: "0 25px 60px -20px rgba(33, 37, 41, 0.35)",
  color: "#1f2933",
};

const LABEL_STYLE = {
  fontSize: 13,
  fontWeight: 600,
  letterSpacing: 0.3,
  textTransform: "uppercase",
  color: "#556272",
  marginBottom: 6,
};

const INPUT_STYLE = {
  width: "100%",
  padding: "12px 14px",
  borderRadius: 10,
  border: "1px solid #d7dde4",
  fontSize: 15,
  color: "#1f2933",
  outline: "none",
  transition: "border 160ms ease, box-shadow 160ms ease",
};

const BUTTON_PRIMARY = {
  width: "100%",
  padding: "12px 16px",
  borderRadius: 10,
  border: "none",
  fontWeight: 600,
  fontSize: 15,
  cursor: "pointer",
  background: "linear-gradient(135deg, #6366f1, #4338ca)",
  color: "white",
  boxShadow: "0 12px 30px -12px rgba(79, 70, 229, 0.7)",
};

const BUTTON_SECONDARY = {
  width: "100%",
  padding: "12px 16px",
  borderRadius: 10,
  border: "1px solid #d7dde4",
  fontWeight: 600,
  fontSize: 15,
  cursor: "pointer",
  background: "white",
  color: "#364152",
};

const SUPPORT_TEXT = {
  fontSize: 13,
  color: "#6b7786",
  textAlign: "center",
};

const LINK_STYLE = {
  color: "#4338ca",
  fontWeight: 600,
  textDecoration: "none",
  cursor: "pointer",
};

const STATUS_STYLE = {
  fontSize: 13,
  marginTop: 16,
  color: "#364152",
  lineHeight: 1.6,
};

const STATUS_COLORS = {
  info: "#2563eb",
  success: "#15803d",
  error: "#dc2626",
};

export default function App() {
  const [mode, setMode] = useState("login");
  useTokenRefresher();

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
        background: "linear-gradient(160deg, #111827 0%, #1f2937 50%, #312e81 100%)",
        fontFamily: "'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      }}
    >
      {mode === "login" ? (
        <LoginCard onSwitchToRegister={() => setMode("register")} />
      ) : (
        <RegisterCard onReturnToLogin={() => setMode("login")} />
      )}
    </div>
  );
}

function LoginCard({ onSwitchToRegister }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [statusTone, setStatusTone] = useState("info");

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  async function handleSubmit(e) {
    e.preventDefault();
    setStatus("");
    setLoading(true);
    try {
      const res = await login(form);
      const message = res.data?.message || "Welcome back!";
      setStatus(message + " Redirecting...");
      setStatusTone("success");
      setTimeout(() => {
        window.location.href = "/";
      }, 650);
    } catch (err) {
      const apiMessage = err.response?.data?.error || err.response?.data?.message;
      setStatus(apiMessage || "Login failed. Check your credentials.");
      setStatusTone("error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={CARD_STYLE}>
      <header style={{ marginBottom: 24 }}>
        <div style={{ fontWeight: 700, fontSize: 18, color: "#1f2933" }}>Sign in to BCord</div>
        <p style={{ fontSize: 13, color: "#6b7786", marginTop: 6 }}>
          Enter your credentials to access the chat dashboard.
        </p>
      </header>

      <form onSubmit={handleSubmit} style={{ display: "grid", gap: 18 }}>
        <label style={{ ...LABEL_STYLE }} htmlFor="login-username">
          Username
        </label>
        <input
          id="login-username"
          name="username"
          value={form.username}
          onChange={handleChange}
          required
          style={INPUT_STYLE}
          placeholder="e.g. aria.stone"
        />

        <label style={{ ...LABEL_STYLE, marginTop: 4 }} htmlFor="login-password">
          Password
        </label>
        <input
          id="login-password"
          type="password"
          name="password"
          value={form.password}
          onChange={handleChange}
          required
          style={INPUT_STYLE}
          placeholder="Enter your password"
        />

        <button type="submit" style={{ ...BUTTON_PRIMARY, marginTop: 12 }} disabled={loading}>
          {loading ? "Signing you in…" : "Login"}
        </button>
      </form>

      <p style={{ ...SUPPORT_TEXT, marginTop: 18 }}>
        Don&apos;t have an account?{" "}
        <span onClick={onSwitchToRegister} style={LINK_STYLE}>
          Create one here
        </span>
      </p>

      {status && (
        <div
          style={{
            ...STATUS_STYLE,
            color: STATUS_COLORS[statusTone] || STATUS_COLORS.info,
          }}
        >
          {status}
        </div>
      )}
    </div>
  );
}

function RegisterCard({ onReturnToLogin }) {
  const [stage, setStage] = useState("details");
  const [form, setForm] = useState({ username: "", password: "", email: "" });
  const [verificationCode, setVerificationCode] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [captchaUrl, setCaptchaUrl] = useState("");
  const [captchaSolution, setCaptchaSolution] = useState("");
  const [captchaInput, setCaptchaInput] = useState("");
  const [statusTone, setStatusTone] = useState("info");

  useEffect(() => {
    loadCaptcha();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    return () => {
      if (captchaUrl) URL.revokeObjectURL(captchaUrl);
    };
  }, [captchaUrl]);

  const maskedEmail = useMemo(() => {
    if (!form.email.includes("@")) return form.email;
    const [name, domain] = form.email.split("@");
    if (!name) return form.email;
    const visible = name.length <= 2 ? name : name.slice(0, 2) + "***";
    return `${visible}@${domain}`;
  }, [form.email]);

  function handleChange(e) {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  }

  async function loadCaptcha() {
    setStatus("");
    setStatusTone("info");
    setCaptchaInput("");
    try {
      if (captchaUrl) URL.revokeObjectURL(captchaUrl);
      const text = randomCaptchaText();
      const res = await axios.post(
        "/captcha",
        {
          text,
          width: 360,
          height: 110,
          difficulty: 3,
        },
        { responseType: "blob" }
      );
      const objectUrl = URL.createObjectURL(res.data);
      setCaptchaUrl(objectUrl);
      setCaptchaSolution(text);
    } catch (err) {
      console.error("captcha load failed", err);
      setStatus("We couldn\'t load the CAPTCHA. Please try again.");
      setStatusTone("error");
      setCaptchaUrl("");
      setCaptchaSolution("");
    }
  }

  function restartFlow() {
    setStage("details");
    setVerificationCode("");
    setCaptchaInput("");
    setStatus("");
    setStatusTone("info");
    loadCaptcha();
  }

  async function handleRegister(e) {
    e.preventDefault();
    if (stage !== "details") return;

    if (!captchaSolution) {
      setStatus("CAPTCHA unavailable. Refresh and try again.");
      setStatusTone("error");
      return;
    }
    if (captchaInput.trim().toUpperCase() !== captchaSolution.toUpperCase()) {
      setStatus("CAPTCHA did not match. Please try again.");
      setStatusTone("error");
      loadCaptcha();
      return;
    }

    setLoading(true);
    setStatus("Creating your account...");
    setStatusTone("info");
    try {
      await register({
        username: form.username,
        password: form.password,
        email: form.email,
        captcha_text: captchaInput.trim(),
      });
      setStage("verify");
      setStatus(
        "We\'ve sent a verification code to your inbox. Enter it below to activate your BCord account."
      );
      setStatusTone("info");
    } catch (err) {
      const apiMessage = err.response?.data?.error || err.response?.data?.message;
      setStatus(apiMessage || "Registration failed. Please review your details and try again.");
      setStatusTone("error");
      loadCaptcha();
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(e) {
    e.preventDefault();
    if (stage !== "verify") return;
    setLoading(true);
    setStatus("Verifying your email...");
    setStatusTone("info");
    try {
      const res = await verify({ username: form.username, code: verificationCode.trim() });
      const message = res.data?.message || "Email verified successfully.";
      setStage("success");
      setStatus(message + " You can now log in.");
      setStatusTone("success");
    } catch (err) {
      const apiMessage = err.response?.data?.error || err.response?.data?.message;
      setStatus(apiMessage || "Verification failed. Check the code and try again.");
      setStatusTone("error");
    } finally {
      setLoading(false);
    }
  }

  function openLoginInNewTab() {
    window.open("/", "_blank", "noopener");
    onReturnToLogin();
  }

  return (
    <div style={{ ...CARD_STYLE, paddingBottom: 28 }}>
      <header style={{ marginBottom: 24 }}>
        <div style={{ fontWeight: 700, fontSize: 18, color: "#1f2933" }}>Create your BCord account</div>
        <p style={{ fontSize: 13, color: "#6b7786", marginTop: 6 }}>
          Complete the steps below to join the community.
        </p>
      </header>

      {stage === "details" && (
        <form onSubmit={handleRegister} style={{ display: "grid", gap: 18 }}>
          <label style={LABEL_STYLE} htmlFor="register-username">
            Username
          </label>
          <input
            id="register-username"
            name="username"
            value={form.username}
            onChange={handleChange}
            required
            style={INPUT_STYLE}
            placeholder="Choose a display name"
          />

          <label style={LABEL_STYLE} htmlFor="register-password">
            Password
          </label>
          <input
            id="register-password"
            type="password"
            name="password"
            value={form.password}
            onChange={handleChange}
            required
            style={INPUT_STYLE}
            placeholder="At least 6 characters"
          />

          <label style={LABEL_STYLE} htmlFor="register-email">
            Email address
          </label>
          <input
            id="register-email"
            type="email"
            name="email"
            value={form.email}
            onChange={handleChange}
            required
            style={INPUT_STYLE}
            placeholder="you@example.com"
          />

          <div>
            <div style={{ ...LABEL_STYLE, marginBottom: 12 }}>Security check</div>
            <div
              style={{
                border: "1px solid #d7dde4",
                borderRadius: 12,
                padding: 16,
                background: "#f5f7fa",
              }}
            >
              {captchaUrl ? (
                <img
                  src={captchaUrl}
                  alt="CAPTCHA challenge"
                  style={{ width: "100%", borderRadius: 8, marginBottom: 12 }}
                />
              ) : (
                <div style={{ fontSize: 13, color: "#6b7786", marginBottom: 12 }}>
                  CAPTCHA loading…
                </div>
              )}
              <div style={{ display: "flex", gap: 10, flexDirection: "column" }}>
                <input
                  value={captchaInput}
                  onChange={(e) => setCaptchaInput(e.target.value)}
                  required
                  style={{ ...INPUT_STYLE, width: "100%" }}
                  placeholder="Enter the characters above"
                />
                <button
                  type="button"
                  onClick={loadCaptcha}
                  style={{
                    ...BUTTON_SECONDARY,
                    padding: "10px 14px",
                    fontSize: 14,
                    fontWeight: 500,
                  }}
                >
                  Refresh CAPTCHA
                </button>
              </div>
            </div>
          </div>

          <button type="submit" style={{ ...BUTTON_PRIMARY, marginTop: 4 }} disabled={loading}>
            {loading ? "Submitting…" : "Register & Verify"}
          </button>
        </form>
      )}

      {stage === "verify" && (
        <form onSubmit={handleVerify} style={{ display: "grid", gap: 18 }}>
          <div style={{ ...SUPPORT_TEXT, textAlign: "left", background: "#f8fafc", padding: 12, borderRadius: 12 }}>
            We sent a 6-digit code to <strong>{maskedEmail}</strong>. Enter it below to activate your account.
          </div>
          <label style={LABEL_STYLE} htmlFor="register-code">
            Verification code
          </label>
          <input
            id="register-code"
            value={verificationCode}
            onChange={(e) => setVerificationCode(e.target.value)}
            required
            style={INPUT_STYLE}
            placeholder="Enter the code from your email"
          />

          <button type="submit" style={{ ...BUTTON_PRIMARY, marginTop: 4 }} disabled={loading}>
            {loading ? "Checking code…" : "Verify email"}
          </button>

          <button
            type="button"
            onClick={restartFlow}
            style={{ ...BUTTON_SECONDARY, marginTop: -6 }}
          >
            Start over
          </button>
        </form>
      )}

      {stage === "success" && (
        <div style={{ display: "grid", gap: 16 }}>
          <div
            style={{
              fontSize: 15,
              color: "#1f2933",
              lineHeight: 1.6,
              textAlign: "center",
            }}
          >
            Your BCord account is ready! Use the buttons below to sign in and start chatting.
          </div>
          <button style={BUTTON_PRIMARY} onClick={onReturnToLogin}>
            Go to login
          </button>
          <button style={BUTTON_SECONDARY} onClick={openLoginInNewTab}>
            Open login in a new tab
          </button>
        </div>
      )}

      <p style={{ ...SUPPORT_TEXT, marginTop: 18 }}>
        Already registered?{" "}
        <span onClick={onReturnToLogin} style={LINK_STYLE}>
          Back to login
        </span>
      </p>

      {status && (
        <div
          style={{
            ...STATUS_STYLE,
            background: "#eef2ff",
            borderRadius: 12,
            padding: "12px 16px",
            marginTop: 18,
            color: STATUS_COLORS[statusTone] || STATUS_COLORS.info,
          }}
        >
          {status}
        </div>
      )}
    </div>
  );
}

function randomCaptchaText() {
  const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 6; i += 1) {
    out += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return out;
}

