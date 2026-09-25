import { api } from "./api.js";

export async function askSecurityAssistant(message, conversationId) {
  const body = { message };
  if (conversationId) {
    body.conversation_id = conversationId;
  }
  const res = await api.post("/ai/chat", body);
  return res.data;
}
