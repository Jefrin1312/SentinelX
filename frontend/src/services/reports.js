import { api } from "./api.js";

export async function fetchReportSummary(params = {}) {
  const res = await api.get("/reports/summary", { params });
  return res.data;
}

export async function exportReportPdf(params = {}) {
  const res = await api.get("/reports/export", { params, responseType: "blob" });
  const disposition = res.headers["content-disposition"] || "";
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match ? match[1] : "sentinelx_report.pdf";
  const blobUrl = window.URL.createObjectURL(res.data);
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(blobUrl);
}