/**
 * TrustShield TanStack Query hooks for URL Scans and Telemetry Reporting.
 * Provides caching, polling intervals (2-3s for active scans), and error handling.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { scanApi } from "@/utils/api";

/**
 * Mutation to initiate or deduplicate a website security scan.
 * Calls POST /api/v1/scans
 */
export function useCreateScan(options = {}) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (url) => {
      const cleanUrl = typeof url === "string" ? url.trim() : url;
      return await scanApi.createScan(cleanUrl);
    },
    onSuccess: (data, variables, context) => {
      // Invalidate recent scans so dashboard reflects the newly queued scan
      queryClient.invalidateQueries({ queryKey: ["recentScans"] });
      if (options.onSuccess) {
        options.onSuccess(data, variables, context);
      }
    },
    onError: (error, variables, context) => {
      if (options.onError) {
        options.onError(error, variables, context);
      }
    },
    ...options,
  });
}

/**
 * Query to poll scan execution progress every 2-3 seconds while queued or running.
 * Calls GET /api/v1/scans/{scanId}
 */
export function useScanStatus(scanId, options = {}) {
  const queryClient = useQueryClient();

  return useQuery({
    queryKey: ["scanStatus", scanId],
    queryFn: async () => {
      if (!scanId) return null;
      return await scanApi.getScanStatus(scanId);
    },
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return 2000;
      // Continue polling every 2 seconds while scan is actively processing
      if (data.status === "queued" || data.status === "running") {
        return 2000;
      }
      // Stop polling when scan reaches a terminal state
      return false;
    },
    refetchIntervalInBackground: true,
    // When completed, immediately invalidate the report query so it fetches fresh data
    select: (data) => {
      if (data && (data.status === "completed" || data.status === "failed")) {
        queryClient.invalidateQueries({ queryKey: ["scanReport", scanId] });
      }
      return data;
    },
    ...options,
  });
}

/**
 * Query to retrieve the complete security telemetry dossier.
 * Calls GET /api/v1/scans/{scanId}/report
 */
export function useScanReport(scanId, options = {}) {
  return useQuery({
    queryKey: ["scanReport", scanId],
    queryFn: async () => {
      if (!scanId || scanId === "scan" || scanId === "1") return null;
      return await scanApi.getScanReport(scanId);
    },
    enabled: Boolean(scanId) && scanId !== "scan" && scanId !== "1",
    staleTime: 30000,
    retry: 2,
    ...options,
  });
}

/**
 * Query to fetch recent scans with pagination.
 * Calls GET /api/v1/scans?limit=10&offset=0
 */
export function useRecentScans({ limit = 10, offset = 0 } = {}, options = {}) {
  return useQuery({
    queryKey: ["recentScans", limit, offset],
    queryFn: async () => {
      return await scanApi.getRecentScans(limit, offset);
    },
    staleTime: 10000,
    ...options,
  });
}
