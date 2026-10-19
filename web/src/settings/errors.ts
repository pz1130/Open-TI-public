import { ApiError } from "../api/client";
import type { ConfigError } from "../api/hooks";

export type SaveConflict =
  | { reason: "version_conflict"; current_version: number; updated_by: string | null }
  | { reason: "project_change"; from: string; to: string; alert_count: number }
  | { reason: "oidc_redirect_change"; redirect_uri: string }
  | { reason: "retention_shortened"; preview: Record<string, number> | null; preview_capped?: boolean; preview_error: string | null }
  | { reason: "encryption_key_missing" };

function detailOf(e: unknown): unknown {
  return e instanceof ApiError ? (e.detail as { detail?: unknown } | undefined)?.detail : undefined;
}

export function conflictOf(e: unknown): SaveConflict | null {
  const d = detailOf(e);
  return e instanceof ApiError && e.status === 409 && d && typeof d === "object" && "reason" in d ? (d as SaveConflict) : null;
}

export function fieldErrors(e: unknown): ConfigError[] {
  const d = detailOf(e);
  return e instanceof ApiError && e.status === 422 && d && typeof d === "object" && "errors" in d
    ? ((d as { errors: ConfigError[] }).errors ?? [])
    : [];
}
