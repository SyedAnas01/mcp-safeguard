export async function health() {
  const res = await fetch("https://api.example.com/health");
  return res.ok;
}
