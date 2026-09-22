import { useEffect, useState } from "react";
import { api, getApiError } from "./api.js";

export async function fetchDashboardSummary() {
  const res = await api.get("/dashboard/summary");
  return res.data;
}

export async function fetchDashboardTimeline(hours = 24) {
  const res = await api.get("/dashboard/timeline", { params: { hours } });
  return res.data;
}

export function useDashboard() {
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetchDashboardSummary(), fetchDashboardTimeline()])
      .then(([summaryData, timelineData]) => {
        if (cancelled) return;
        setSummary(summaryData);
        setTimeline(timelineData);
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
  }, []);

  return { summary, timeline, loading, error };
}