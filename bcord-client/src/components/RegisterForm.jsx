import React, { useState } from "react";
import axios from "axios";
import { register } from "../api";

export function RegisterForm() {
  const [form, setForm] = useState({ username: "", password: "", email: "", captcha_text: "" });
  const [msg, setMsg] = useState("");
  const [previewUrl, setPreviewUrl] = useState("");

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  async function previewCaptcha() {
    try {
      const res = await axios.post(
        "/captcha",
        { text: form.captcha_text || "abc", width: 400, height: 100, difficulty: 1 },
        { responseType: "blob" }
      );
      setPreviewUrl(URL.createObjectURL(res.data));
    } catch {
      setMsg("Failed to load captcha preview.");
    }
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setMsg("Submitting...");
    try {
      const res = await register(form);
      setMsg(res.data.message || "Registered!");
    } catch (err) {
      setMsg(err.response?.data?.error || "Error");
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: "grid", gap: 8 }}>
      <input name="username" placeholder="Username" onChange={handleChange} required />
      <input name="password" type="password" placeholder="Password" onChange={handleChange} required />
      <input name="email" type="email" placeholder="Email" onChange={handleChange} required />
      <div>
        <input name="captcha_text" placeholder="Captcha Text" onChange={handleChange} required />
        <button type="button" onClick={previewCaptcha}>Preview CAPTCHA</button>
      </div>
      {previewUrl && <img src={previewUrl} alt="captcha" style={{ marginTop: 10, maxWidth: "100%" }} />}
      <button type="submit">Register</button>
      <p>{msg}</p>
    </form>
  );
}

