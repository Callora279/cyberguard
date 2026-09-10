import useSWR from "swr";
import { fetcher } from "../lib/api";

export function useOnboarding() {
  const { data, error, isLoading, mutate } = useSWR("/onboarding/status", fetcher, {
    revalidateOnFocus: false,
  });
  return {
    status: data,
    completed: data?.completed ?? true, // assume done until we know otherwise
    currentStep: data?.current_step ?? 1,
    steps: data?.steps ?? [],
    scanCount: data?.scan_count ?? 0,
    openFindings: data?.open_findings ?? 0,
    plan: data?.plan,
    trialEndsAt: data?.trial_ends_at,
    loading: isLoading,
    error,
    refresh: mutate,
  };
}
