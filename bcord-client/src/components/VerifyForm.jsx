import React, { useState } from "react";
import { verify } from "../api";

export function VerifyForm() {
  const [form, setForm] = useState({ username: "", code: "" });
  const [msg, setMsg] = useState("");

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  async function handleSubmit(e) {
    e.preventDefault();
    setMsg("Verifying...");
    try {
      const res = await verify(form);
      setMsg(res.data.message || "Verified!");
    } catch (err) {
      setMsg(err.response?.data?.error || "Error");
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: "grid", gap: 8 }}>
      <input name="username" placeholder="Username" onChange={handleChange} required />
      <input name="code" placeholder="Verification Code" onChange={handleChange} required />
      <button type="submit">Verify Email</button>
      <p>{msg}</p>
    </form>
  );
}

