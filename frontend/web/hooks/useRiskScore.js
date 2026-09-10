import useSWR from "swr";
import { fetcher } from "../lib/api";

export function useRiskScore() {
  const { data, error, isLoading, mutate } = useSWR("/risk-score/dashboard", fetcher, {
    refreshInterval: 30000,
  });
  return {
    score: data?.score,
    grade: data?.grade,
    breakdown: data?.breakdown || {},
    trend: data?.trend_30d || [],
    forecast: data?.forecast,
    recommendations: data?.recommendations || [],
    alertFeed: data?.alert_feed || [],
    loading: isLoading,
    error,
    refresh: mutate,
  };
}

export function useRiskHistory(days = 30) {
  const { data } = useSWR(`/risk-score/history?days=${days}`, fetcher);
  return { series: data?.series || [], trend: data?.trend };
}
