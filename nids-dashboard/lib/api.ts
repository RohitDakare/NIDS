// lib/api.ts

const API_BASE_URL = process.env.NEXT_PUBLIC_NIDS_API_URL || "http://localhost:8000/api/v1";

export async function fetchAlerts(limit = 50) {
  const res = await fetch(`${API_BASE_URL}/alerts?limit=${limit}`);
  if (!res.ok) throw new Error("Failed to fetch alerts");
  return res.json();
}

export async function fetchPackets(limit = 100) {
  const res = await fetch(`${API_BASE_URL}/packets?limit=${limit}`);
  if (!res.ok) throw new Error("Failed to fetch packets");
  return res.json();
}

export async function fetchSystemStatus() {
  const res = await fetch(`${API_BASE_URL}/status`);
  if (!res.ok) throw new Error("Failed to fetch system status");
  return res.json();
}

export async function startSniffer(config?: any) {
  const res = await fetch(`${API_BASE_URL}/start-sniffer`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ config }),
  });
  if (!res.ok) throw new Error("Failed to start sniffer");
  return res.json();
}

export async function stopSniffer() {
  const res = await fetch(`${API_BASE_URL}/stop-sniffer`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to stop sniffer");
  return res.json();
}

export async function resolveAlert(alertId: string, resolutionNotes = "") {
  const res = await fetch(`${API_BASE_URL}/alerts/${alertId}/resolve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ resolution_notes: resolutionNotes }),
  });
  if (!res.ok) throw new Error("Failed to resolve alert");
  return res.json();
}

export async function deleteAlert(alertId: string) {
  const res = await fetch(`${API_BASE_URL}/alerts/${alertId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete alert");
  return res.json();
}

export async function clearAlerts(olderThanDays?: number) {
  const url = olderThanDays
    ? `${API_BASE_URL}/alerts/clear?older_than_days=${olderThanDays}`
    : `${API_BASE_URL}/alerts/clear`;
  const res = await fetch(url, { method: "POST" });
  if (!res.ok) throw new Error("Failed to clear alerts");
  return res.json();
}

export async function fetchStats() {
  const res = await fetch(`${API_BASE_URL}/stats`);
  if (!res.ok) throw new Error("Failed to fetch stats");
  return res.json();
}

export async function fetchCorrelation() {
  const res = await fetch(`${API_BASE_URL}/correlation`);
  if (!res.ok) throw new Error("Failed to fetch correlation analysis");
  return res.json();
}

export async function fetchSignatureRules() {
  const res = await fetch(`${API_BASE_URL}/signature-rules`);
  if (!res.ok) throw new Error("Failed to fetch signature rules");
  return res.json();
}

export async function enableSignatureRule(ruleId: string) {
  const res = await fetch(`${API_BASE_URL}/signature-rules/${ruleId}/enable`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to enable signature rule");
  return res.json();
}

export async function disableSignatureRule(ruleId: string) {
  const res = await fetch(`${API_BASE_URL}/signature-rules/${ruleId}/disable`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to disable signature rule");
  return res.json();
} 