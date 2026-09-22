import { api } from "./api.js";

export async function fetchInvestigations(params = {}) {
  const res = await api.get("/investigations", { params });
  return res.data;
}

export async function fetchInvestigation(id) {
  const res = await api.get(`/investigations/${id}`);
  return res.data;
}

export async function createInvestigation(payload) {
  const res = await api.post("/investigations", payload);
  return res.data;
}

export async function updateInvestigation(id, payload) {
  const res = await api.patch(`/investigations/${id}`, payload);
  return res.data;
}

export async function addInvestigationNote(id, note) {
  const res = await api.post(`/investigations/${id}/notes`, { note });
  return res.data;
}