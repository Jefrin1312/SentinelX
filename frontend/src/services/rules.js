import { api } from "./api.js";

export async function fetchRules(params = {}) {
  const res = await api.get("/rules", { params });
  return res.data;
}

export async function setRuleEnabled(id, enabled) {
  const res = await api.patch(`/rules/${id}`, { enabled });
  return res.data;
}

export async function createRule(payload) {
  const res = await api.post("/rules", payload);
  return res.data;
}

export async function reloadRules() {
  const res = await api.post("/rules/reload");
  return res.data;
}