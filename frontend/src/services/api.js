import axios from "axios";

const api = axios.create({
  baseURL: "/api",
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

export { api, getApiError };