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
    // 1️⃣ 提交 URL 做分析
    const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VIRUSTOTAL_API,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    const submitData = await submitResponse.json();

    if (!submitData.data || !submitData.data.id) {
      return res.status(500).json({ error: "Failed to submit URL to VirusTotal" });
    }

    const analysisId = submitData.data.id;

    // 2️⃣ 轮询等待扫描完成（最多等 30 秒）
    let analysisData = null;
    for (let i = 0; i < 10; i++) {
      // 每次等 3 秒
      await new Promise(resolve => setTimeout(resolve, 3000));

      const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        method: "GET",
        headers: { "x-apikey": VIRUSTOTAL_API },
      });

      analysisData = await analysisResponse.json();
      const status = analysisData.data?.attributes?.status;

      console.log(`[VirusTotal] Attempt ${i + 1}, status: ${status}`);

      // 扫描完成就跳出循环
      if (status === "completed") break;
    }

    // 3️⃣ 判断 malicious
    const stats = analysisData?.data?.attributes?.stats || {};
    const malicious = (stats.malicious || 0) > 0;

    res.json({ stats, malicious, analysisId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to scan URL with VirusTotal" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 VirusTotal backend running on port ${PORT}`);
});
