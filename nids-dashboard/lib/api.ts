// lib/api.ts

const API_BASE_URL = process.env.NEXT_PUBLIC_NIDS_API_URL || "http://localhost:8000/api/v1";
const API_KEY = process.env.NEXT_PUBLIC_NIDS_API_KEY || "nids-dev-api-key-12345678901234567890123456789012";

// Helper function to get auth headers
function getAuthHeaders() {
  return {
    "Authorization": `Bearer ${API_KEY}`,
    "Content-Type": "application/json",
  };
}

export async function fetchAlerts(limit = 50) {
  const res = await fetch(`${API_BASE_URL}/alerts?limit=${limit}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch alerts");
  return res.json();
}

export async function fetchPackets(limit = 100) {
  const res = await fetch(`${API_BASE_URL}/packets?limit=${limit}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch packets");
  return res.json();
}

export async function fetchSystemStatus() {
  const res = await fetch(`${API_BASE_URL}/status`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch system status");
  return res.json();
}

export async function startSniffer(config?: any) {
  const res = await fetch(`${API_BASE_URL}/start-sniffer`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify({ config }),
  });
  if (!res.ok) throw new Error("Failed to start sniffer");
  return res.json();
}

export async function stopSniffer() {
  const res = await fetch(`${API_BASE_URL}/stop-sniffer`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to stop sniffer");
  return res.json();
}

export async function resolveAlert(alertId: string, resolutionNotes = "") {
  const res = await fetch(`${API_BASE_URL}/alerts/${alertId}/resolve`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify({ resolution_notes: resolutionNotes }),
  });
  if (!res.ok) throw new Error("Failed to resolve alert");
  return res.json();
}

export async function deleteAlert(alertId: string) {
  const res = await fetch(`${API_BASE_URL}/alerts/${alertId}`, {
    method: "DELETE",
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to delete alert");
  return res.json();
}

export async function clearAlerts(olderThanDays?: number) {
  const url = olderThanDays
    ? `${API_BASE_URL}/alerts/clear?older_than_days=${olderThanDays}`
    : `${API_BASE_URL}/alerts/clear`;
  const res = await fetch(url, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to clear alerts");
  return res.json();
}

export async function fetchStats() {
  const res = await fetch(`${API_BASE_URL}/stats`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch stats");
  return res.json();
}

export async function fetchCorrelation() {
  const res = await fetch(`${API_BASE_URL}/correlation`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch correlation analysis");
  return res.json();
}

export async function fetchSignatureRules() {
  const res = await fetch(`${API_BASE_URL}/signature-rules`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch signature rules");
  return res.json();
}

export async function enableSignatureRule(ruleId: string) {
  const res = await fetch(`${API_BASE_URL}/signature-rules/${ruleId}/enable`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to enable signature rule");
  return res.json();
}

export async function disableSignatureRule(ruleId: string) {
  const res = await fetch(`${API_BASE_URL}/signature-rules/${ruleId}/disable`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error("Failed to disable signature rule");
  return res.json();
}

// Settings and control helpers
export async function startSnifferWithConfig(config?: any) {
  // Alias to startSniffer for clarity
  return startSniffer(config);
}

export async function stopSnifferApi() {
  // Alias to stopSniffer for clarity
  return stopSniffer();
}

export async function updateSnifferConfig(config: any) {
  const res = await fetch(`${API_BASE_URL}/config/sniffer`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify(config),
  });
  if (!res.ok) throw new Error("Failed to update sniffer config");
  return res.json();
}

export async function updateMLConfig(config: any) {
  const res = await fetch(`${API_BASE_URL}/config/ml`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify(config),
  });
  if (!res.ok) throw new Error("Failed to update ML config");
  return res.json();
}