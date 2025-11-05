import axios from "axios";

export const api = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" }
});

api.interceptors.request.use(config => {
  const token = localStorage.getItem("jwt");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export async function register(data) { return api.post("/auth/register", data); }
export async function verify(data)   { return api.post("/auth/verify", data); }
export async function login(data)    { return api.post("/auth/login", data); }
export async function profile()      { return api.get("/profile"); }

