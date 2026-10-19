import createClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./schema";

export type Schemas = components["schemas"];

let activeProject: string | undefined;
export function setActiveProject(project: string) {
  activeProject = project;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly detail: unknown,
  ) {
    super(`HTTP ${status}`);
  }
}

const csrf: Middleware = {
  onRequest({ request }) {
    request.headers.set("X-Requested-With", "opti");
    if (activeProject && ["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) request.headers.set("X-Opti-Project", activeProject);
    return request;
  },
};

// 同源访问；会话在 HttpOnly Cookie 中，前端拿不到令牌
export const api = createClient<paths>({ baseUrl: window.location.origin, credentials: "same-origin", fetch: (...args) => globalThis.fetch(...args) });
api.use(csrf);

export function unwrap<T>(r: { data?: T; error?: unknown; response: Response }): T {
  if (!r.response.ok) throw new ApiError(r.response.status, r.error);
  return r.data as T;
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    const d = (e.detail as { detail?: unknown } | undefined)?.detail;
    if (typeof d === "string") return d;
    if (d && typeof d === "object" && "message" in d) return String((d as { message: unknown }).message);
    // 配置校验错误：{ errors: [{ path, message }] }，显示出错位置与原因
    if (d && typeof d === "object" && "errors" in d && Array.isArray((d as { errors: unknown }).errors)) {
      return (d as { errors: { path?: string; message?: unknown }[] }).errors
        .map((x) => (x.path ? `${x.path}：${String(x.message)}` : String(x.message)))
        .join("；");
    }
    return e.message;
  }
  return e instanceof Error ? e.message : String(e);
}
