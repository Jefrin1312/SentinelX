import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "/api",
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("sentinelx_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("sentinelx_token");
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