import { api, downloadCsv } from "./api.js";

export async function fetchAuditLogs(params = {}) {
  const res = await api.get("/audit-logs", { params });
  return res.data;
}

export async function exportAuditLogs(params = {}) {
  await downloadCsv("/audit-logs/export", params, "audit-logs.csv");
}