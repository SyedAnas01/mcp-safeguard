import ipaddr from "ipaddr.js";
import dns from "node:dns/promises";
async function assertPublic(host: string) {
  const { address } = await dns.lookup(host);
  const a = ipaddr.parse(address);
  if (a.range() !== "unicast") throw new Error("blocked: isPrivate range");
}
export async function loadClientMetadata(clientId: string) {
  const u = new URL(clientId);
  if (u.protocol !== "https:") throw new Error("https only");
  await assertPublic(u.hostname);
  const res = await fetch(u, { redirect: "error" });
  return res.json();
}
