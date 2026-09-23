import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "/api",
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
});

function getCookie(name) {
  const match = document.cookie.match(
    new RegExp(`(?:^|;\\s*)${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}=([^;]*)`)
  );
  return match ? decodeURIComponent(match[1]) : null;
}

api.interceptors.request.use((config) => {
  // Double-submit CSRF: the (non-HttpOnly) sentinelx_csrf cookie set at login is
  // echoed back as an X-CSRF-Token header on state-changing requests. The JWT
  // itself lives only in the HttpOnly cookie and never touches JavaScript.
  const method = (config.method || "get").toUpperCase();
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    const csrf = getCookie("sentinelx_csrf");
    if (csrf) {
      config.headers["X-CSRF-Token"] = csrf;
    }
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Notify React state so the UI updates immediately; the redirect is a
      // safety net for non-React consumers.
      window.dispatchEvent(new CustomEvent("sentinelx:unauthorized"));
      const current = window.location.pathname;
      if (current !== "/login" && current !== "/register") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

function getApiError(error) {
  const detail = error.response?.data?.detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => d.msg).join(", ");
  }
  if (typeof detail === "string") {
    return detail;
  }
  return error.message || "Something went wrong. Please try again.";
}

export async function downloadCsv(url, params = {}, fallbackName) {
  const res = await api.get(url, { params, responseType: "blob" });
  const disposition = res.headers["content-disposition"] || "";
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match ? match[1] : fallbackName;
  const blobUrl = window.URL.createObjectURL(res.data);
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(blobUrl);
}

export { api, getApiError };