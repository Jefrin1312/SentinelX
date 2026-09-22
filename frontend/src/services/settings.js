import { api } from "./api.js";

export async function fetchSettings() {
  const res = await api.get("/settings");
  return res.data;
}