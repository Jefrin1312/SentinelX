import { api } from "./api.js";

export async function fetchAuditLogs(params = {}) {
  const res = await api.get("/audit-logs", { params });
  return res.data;
}