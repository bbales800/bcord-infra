import axios from "axios";

const API_BASE = "/api";

let accessToken = localStorage.getItem("accessToken");
let refreshToken = localStorage.getItem("refreshToken");

export const api = axios.create({
  baseURL: API_BASE,
  headers: { "Content-Type": "application/json" },
});

// attach token to every request
api.interceptors.request.use((config) => {
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`;
  return config;
});

// refresh handler
async function refreshAccessToken() {
  if (!refreshToken) return null;
  try {
    const res = await axios.post(`${API_BASE}/auth/refresh`, { refresh_token: refreshToken });
    accessToken = res.data.access_token;
    localStorage.setItem("accessToken", accessToken);
    return accessToken;
  } catch (err) {
    console.error("refresh failed:", err.response?.data || err.message);
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
    return null;
  }
}

// response interceptor – auto-refresh once on 401
api.interceptors.response.use(
  (r) => r,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      const newToken = await refreshAccessToken();
      if (newToken) {
        original.headers.Authorization = `Bearer ${newToken}`;
        return api(original);
      }
    }
    return Promise.reject(error);
  }
);

// ---- API helpers ----
export async function register(data) {
  return api.post("/auth/register", data);
}

export async function verify(data) {
  return api.post("/auth/verify", data);
}

export async function login(data) {
  const res = await api.post("/auth/login", data);
  // server should now return refresh_token + access token
  if (res.data.token) localStorage.setItem("accessToken", res.data.token);
  if (res.data.refresh_token) localStorage.setItem("refreshToken", res.data.refresh_token);
  return res;
}

export async function logout() {
  const token = localStorage.getItem("refreshToken");
  if (token) await api.post("/auth/logout", { refresh_token: token });
  localStorage.removeItem("accessToken");
  localStorage.removeItem("refreshToken");
}

export async function getProfile() {
  return api.get("/profile");
}

