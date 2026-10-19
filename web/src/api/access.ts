import { useQuery } from "@tanstack/react-query";
import { api, unwrap, type Schemas } from "./client";

export type ManagedUser = Schemas["UserOut"];
export type AccessRole = Schemas["AccessRoleOut"];
export type PermissionSet = Schemas["PermissionSetOut"];
export const accessKey = ["access"] as const;

export function useAccessCatalog() {
  return useQuery({ queryKey: [...accessKey, "catalog"], queryFn: async () => unwrap(await api.GET("/api/v1/admin/access")) });
}

export function useUsers(q: string, page: number, limit: number) {
  return useQuery({ queryKey: [...accessKey, "users", q, page, limit], queryFn: async () => unwrap(await api.GET("/api/v1/admin/users", { params: { query: { q, page, limit } } })) });
}
