import { useEffect } from "react";
import { api } from "../api";

// Assumes your api helper uses fetch/axios.
// If using fetch directly, add { credentials: 'include' } on requests
// to send cookies and receive Set-Cookie in responses.
export default function useTokenRefresher(intervalMinutes = 5) {
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        // No body required if backend reads BCORD_REFRESH cookie server-side.
        // If your backend expects JSON, send an empty object.
        const res = await fetch("/api/auth/refresh", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include", // <-- important for cookies
          body: JSON.stringify({}) // backend uses cookie; body is ignored
        });
        // We don't need to read the body; Set-Cookie sets BCORD_ACCESS.
        if (!res.ok) {
          console.warn("token refresh failed");
        }
      } catch {
        console.warn("token refresh failed");
      }
    }, intervalMinutes * 60 * 1000);

    return () => clearInterval(interval);
  }, [intervalMinutes]);
}

