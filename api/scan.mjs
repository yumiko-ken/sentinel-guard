import { scanToken, CHAINS } from "../lib/scan.mjs";

export default async function handler(req, res) {
  res.setHeader("content-type", "application/json; charset=utf-8");
  try {
    const url = new URL(req.url, "http://localhost");
    const chain = (url.searchParams.get("chain") || "").toLowerCase();
    const token = url.searchParams.get("token") || "";
    if (!CHAINS[chain]) {
      res.status(400).json({ error: "Invalid chain — use ?chain=bsc or ?chain=ethereum" });
      return;
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(token)) {
      res.status(400).json({ error: "Invalid token address — expected 0x followed by 40 hex characters" });
      return;
    }
    const report = await scanToken(chain, token);
    res.status(200).json(report);
  } catch (e) {
    const status = e && e.status ? e.status : 502;
    res.status(status).json({ error: String(e && e.message ? e.message : e) });
  }
}
