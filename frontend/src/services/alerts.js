import { useEffect, useState } from "react";
import { api, downloadCsv, getApiError } from "./api.js";

export async function fetchAlerts(params = {}) {
  const res = await api.get("/alerts", { params });
  return res.data;
}

export async function fetchAlert(id) {
  const res = await api.get(`/alerts/${id}`);
  return res.data;
}

export async function updateAlertStatus(id, status, note) {
  const res = await api.patch(`/alerts/${id}/status`, { status, note });
  return res.data;
}

export async function exportAlerts(params = {}) {
  await downloadCsv("/alerts/export", params, "alerts.csv");
}

export function useAlerts(filters, page) {
  const { limit, offset } = page;
  const [data, setData] = useState({ total: 0, items: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    const params = { ...filters, limit, skip: offset };
    setLoading(true);
    fetchAlerts(params)
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
  }, [filters, limit, offset]);

  return { data, loading, error };
}