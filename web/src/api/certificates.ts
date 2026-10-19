import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, unwrap, type Schemas } from "./client";

const monitorsKey = ["certificate-monitors"] as const;
const hostsKey = ["certificate-hosts"] as const;

export function useCertificateMonitors(page = 1, pageSize = 20) {
  return useQuery({
    queryKey: [...monitorsKey, page, pageSize],
    queryFn: async () => unwrap(await api.GET("/api/v1/certificate-monitors", {
      params: { query: { page, limit: pageSize } },
    })),
    refetchInterval: 5000,
  });
}

export function useCertificateHosts(id: number | null, q: string, page = 1, pageSize = 20, order: "id" | "expiry_asc" | "expiry_desc" = "id", approval: "all" | "pending" | "approved" = "all") {
  return useQuery({
    queryKey: [...hostsKey, id, q, page, pageSize, order, approval],
    queryFn: async () => unwrap(await api.GET("/api/v1/certificate-monitors/{monitor_id}/hosts", {
      params: { path: { monitor_id: id as number }, query: { page, limit: pageSize, order, approval, q: q || undefined } },
    })),
    enabled: id !== null,
    refetchInterval: 5000,
  });
}

export function useConfigureCertificateHost() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ monitorId, hostId, body }: { monitorId: number; hostId: number; body: Schemas["CertificateHostConfig"] }) => unwrap(await api.PUT(
      "/api/v1/certificate-monitors/{monitor_id}/hosts/{host_id}",
      { params: { path: { monitor_id: monitorId, host_id: hostId } }, body },
    )),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: hostsKey });
      void qc.invalidateQueries({ queryKey: monitorsKey });
    },
  });
}

export function useSaveCertificateMonitor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id?: number; body: Schemas["CertificateMonitorIn"] }) => id === undefined
      ? unwrap(await api.POST("/api/v1/certificate-monitors", { body }))
      : unwrap(await api.PUT("/api/v1/certificate-monitors/{monitor_id}", { params: { path: { monitor_id: id } }, body })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: monitorsKey });
      void qc.invalidateQueries({ queryKey: hostsKey });
    },
  });
}

export function useCheckCertificateMonitor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => unwrap(await api.POST("/api/v1/certificate-monitors/{monitor_id}/check", { params: { path: { monitor_id: id } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: monitorsKey }),
  });
}

export function useRemoveCertificateMonitor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => unwrap(await api.DELETE("/api/v1/certificate-monitors/{monitor_id}", { params: { path: { monitor_id: id } } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: monitorsKey });
      void qc.invalidateQueries({ queryKey: hostsKey });
    },
  });
}
