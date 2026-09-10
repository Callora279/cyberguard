import useSWR from "swr";
import { api, fetcher } from "../lib/api";

export function useAlerts(filters = {}) {
  const qs = new URLSearchParams(filters).toString();
  const { data, error, isLoading, mutate } = useSWR(
    `/alerts${qs ? `?${qs}` : ""}`,
    fetcher,
    { refreshInterval: 15000 }
  );

  async function acknowledge(id) {
    await api(`/alerts/${id}/acknowledge`, { method: "PUT" });
    mutate();
  }

  return {
    alerts: data?.alerts || [],
    count: data?.count || 0,
    loading: isLoading,
    error,
    acknowledge,
    refresh: mutate,
  };
}
