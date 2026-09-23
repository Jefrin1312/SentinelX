import { useEffect, useState } from "react";
import { api, downloadCsv, getApiError } from "./api.js";

export async function fetchEvents(params = {}) {
  const res = await api.get("/logs", { params });
  return res.data;
}

export async function exportEvents(params = {}) {
  await downloadCsv("/logs/export", params, "events.csv");
}

export async function ingestLines(lines, source = "MANUAL") {
  const res = await api.post("/logs/ingest", { lines, source });
  return res.data;
}

export async function uploadLogFile(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await api.post("/logs/upload", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return res.data;
}

export async function importSample(sample) {
  const res = await api.post("/logs/import", null, { params: { sample } });
  return res.data;
}

export async function clearMyImportedData() {
  const res = await api.delete("/logs/mine");
  return res.data;
}

export function useLogs(filters, page, refreshKey = 0) {
  const { limit, offset } = page;
  const [data, setData] = useState({ total: 0, items: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    const params = {
      ...filters,
      limit,
      skip: offset,
    };
    setLoading(true);
    fetchEvents(params)
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .catch((err) => {
        if (!cancelled) setError(getApiError(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [filters, limit, offset, refreshKey]);

  return { data, loading, error };
}