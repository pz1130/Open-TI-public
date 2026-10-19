/** 告警推送表单的辅助函数：渠道 ID 生成与密钥键名。 */

export type SecretDraft = Record<string, string | null>;

export function slugify(name: string, fallback: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32).replace(/-+$/, "");
  return slug || fallback;
}

export const secretName = (channelId: string) => `channel:${channelId}:webhook_url`;

const parkedSecret = (fieldKey: number) => `\0field:${fieldKey}`;

/** 未保存渠道的 Webhook 草稿跟着 ID 走。ID 暂时为空时先挂起，避免旧键留在提交里。 */
export function moveChannelSecret(drafts: SecretDraft, fieldKey: number, prevId: string, nextId: string): SecretDraft {
  if (prevId === nextId) return drafts;
  const park = parkedSecret(fieldKey);
  const from = prevId && secretName(prevId) in drafts ? secretName(prevId) : park in drafts ? park : "";
  if (!from) return drafts;
  const dest = nextId ? secretName(nextId) : park;
  if (from === dest) return drafts;
  const next = { ...drafts, [dest]: drafts[from] };
  delete next[from];
  return next;
}

export function dropChannelSecret(drafts: SecretDraft, fieldKey: number, ...channelIds: string[]): SecretDraft {
  const park = parkedSecret(fieldKey);
  if (!(park in drafts) && !channelIds.some((id) => id && secretName(id) in drafts)) return drafts;
  const next = { ...drafts };
  delete next[park];
  for (const id of channelIds) if (id) delete next[secretName(id)];
  return next;
}

export function publishableSecrets(drafts: SecretDraft): SecretDraft {
  return Object.fromEntries(Object.entries(drafts).filter(([k]) => !k.startsWith("\0")));
}
