import { api } from "./api.js";

export async function fetchReportSummary(params = {}) {
  const res = await api.get("/reports/summary", { params });
  return res.data;
}