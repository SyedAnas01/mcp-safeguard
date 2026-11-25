// CIMD: client_id is an https URL naming the client metadata document.
export async function loadClientMetadata(clientId: string) {
  const res = await fetch(clientId, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error("metadata fetch failed");
  return res.json();
}
