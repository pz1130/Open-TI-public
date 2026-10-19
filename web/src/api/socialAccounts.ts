import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, unwrap, type Schemas } from "./client";

const accountsKey = ["protected-accounts"] as const;
const candidatesKey = ["account-candidates"] as const;
export type CandidateSeverity = "low" | "medium" | "high" | "critical";

export function useProtectedAccounts(page = 1, pageSize = 20) {
  return useQuery({
    queryKey: [...accountsKey, page, pageSize],
    queryFn: async () => unwrap(await api.GET("/api/v1/protected-accounts", {
      params: { query: { page, limit: pageSize } },
    })),
    refetchInterval: 5000,
  });
}

export function useAccountCandidates(id: number | null, severity: CandidateSeverity | undefined, page = 1, pageSize = 20, order: "id" | "score_asc" | "score_desc" = "score_desc") {
  return useQuery({
    queryKey: [...candidatesKey, id, severity, page, pageSize, order],
    queryFn: async () => unwrap(await api.GET("/api/v1/protected-accounts/{account_id}/candidates", {
      params: { path: { account_id: id as number }, query: { page, limit: pageSize, severity, order } },
    })),
    enabled: id !== null,
    refetchInterval: 5000,
  });
}

export function useSaveProtectedAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id?: number; body: Schemas["ProtectedAccountIn"] }) => id === undefined
      ? unwrap(await api.POST("/api/v1/protected-accounts", { body }))
      : unwrap(await api.PUT("/api/v1/protected-accounts/{account_id}", { params: { path: { account_id: id } }, body })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: accountsKey });
      void qc.invalidateQueries({ queryKey: candidatesKey });
    },
  });
}

export function useCheckProtectedAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => unwrap(await api.POST("/api/v1/protected-accounts/{account_id}/check", { params: { path: { account_id: id } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: accountsKey }),
  });
}

export function useRemoveProtectedAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => unwrap(await api.DELETE("/api/v1/protected-accounts/{account_id}", { params: { path: { account_id: id } } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: accountsKey });
      void qc.invalidateQueries({ queryKey: candidatesKey });
    },
  });
}
