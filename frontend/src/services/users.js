import { api } from "./api.js";

export async function fetchUsers(params = {}) {
  const res = await api.get("/users", { params });
  return res.data;
}

export async function updateUser(id, payload) {
  const res = await api.patch(`/users/${id}`, payload);
  return res.data;
}