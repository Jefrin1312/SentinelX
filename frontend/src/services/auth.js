import { api } from "./api.js";

export async function updateProfile(payload) {
  const res = await api.patch("/auth/me", payload);
  return res.data;
}

export async function changePassword(currentPassword, newPassword) {
  await api.post("/auth/change-password", {
    current_password: currentPassword,
    new_password: newPassword,
  });
}