import React, { useState } from "react";
import axios from "axios";
import { register } from "../api";

export function RegisterForm() {
  const [form, setForm] = useState({
    username: "",
    password: "",
    email: "",
    captcha_text: ""
  });
  const [msg, setMsg] = useState("");
  const [previewUrl, setPreviewUrl] = useState("");

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  async function previewCaptcha() {
    try {
      const res = await axios.post(
        "/captcha",
        {
          text: form.captcha_text || "ABC123",
          width: 400,
          height: 100,
          difficulty: 2
        },
        { responseType: "blob" }
      );
      const url = URL.createObjectURL(res.data);
      setPreviewUrl(url);
      setMsg("Click image to reload if unclear");
    } catch (err) {
      console.error(err);
      setMsg("⚠️ Failed to load CAPTCHA");
    }
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setMsg("Submitting...");
    try {
      const res = await register(form);
      setMsg(res.data.message || "Registered!");
    } catch (err) {
      setMsg(err.response?.data?.error || "Registration failed");
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      style={{
        display: "grid",
        gap: 8,
        maxWidth: 400,
        margin: "2rem auto",
        textAlign: "center"
      }}
    >
      <input name="username" placeholder="Username" onChange={handleChange} required />
      <input name="password" type="password" placeholder="Password" onChange={handleChange} required />
      <input name="email" type="email" placeholder="Email" onChange={handleChange} required />

      <div>
        {previewUrl ? (
          <img
            src={previewUrl}
            alt="captcha"
            style={{ width: "100%", borderRadius: 4, cursor: "pointer" }}
            onClick={previewCaptcha}
            title="Click to reload CAPTCHA"
          />
        ) : (
          <button type="button" onClick={previewCaptcha}>
            Load CAPTCHA
          </button>
        )}
        <input
          name="captcha_text"
          placeholder="Enter CAPTCHA Text"
          onChange={handleChange}
          required
          style={{ marginTop: 8 }}
        />
      </div>

      <button type="submit">Register</button>
      <p>{msg}</p>
    </form>
  );
}

