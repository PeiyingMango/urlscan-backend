import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;
const VIRUSTOTAL_API = process.env.VIRUSTOTAL_API;

if (!VIRUSTOTAL_API) {
  console.error("⚠️ VIRUSTOTAL_API not set in environment variables!");
  process.exit(1);
}  

app.use(cors());
app.use(express.json());

app.post("/api/virustotal", async (req, res) => {
  const { url } = req.body;

  if (!url) return res.status(400).json({ error: "URL is required" });

  try {
    // 使用 https://www.virustotal.com 的 search API 检查这个 URL 是否已经在 VIRUSTOTAL 数据库中
    const searchUrl = `https://www.virustotal.com/api/v3/search/?q=url:"${encodeURIComponent(
      url
    )}"`;

    const response = await fetch(searchUrl, {
      method: "GET",
      headers: {
        "API-Key": VIRUSTOTAL_API
      }
    });

    const data = await response.json();

    // 如果 total > 0，说明这个 URL 在 urlscan.io 中有记录
    // 按你论文的设计：视为 malicious（黑名单），前端就会弹 warning.html
    const malicious = typeof data.total === "number" && data.total > 0;

    res.json({ ...data, malicious });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to scan URL" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 urlscan backend running on port ${PORT}`);
});