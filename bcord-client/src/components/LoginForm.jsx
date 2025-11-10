import React, { useState } from "react";
import { login } from "../api";

export function LoginForm() {
  const [form, setForm] = useState({ username: "", password: "" });
  const [msg, setMsg] = useState("");

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  async function handleSubmit(e) {
    e.preventDefault();
    try {
      const res = await login(form);
      const { message, token, refresh_token } = res.data;
      if (token) localStorage.setItem("accessToken", token);
      if (refresh_token) localStorage.setItem("refreshToken", refresh_token);
      setMsg(message || "Login successful!");
    } catch (err) {
      setMsg(err.response?.data?.message || "Login failed");
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="username" placeholder="Username" onChange={handleChange} required />
      <input name="password" type="password" placeholder="Password" onChange={handleChange} required />
      <button type="submit">Login</button>
      <p>{msg}</p>
    </form>
  );
}

