import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;
const URLSCAN_API = process.env.VIRUSTOTAL_API; // URLScan API key

if (!URLSCAN_API) {
  console.error("⚠️ URLSCAN_API not set in environment variables!");
  process.exit(1);
}

app.use(cors());
app.use(express.json());

// ===============================
// Cache（内存）
// ===============================
const urlCache = new Map();
const CACHE_TTL = 1000 * 60 * 30; // 30分钟

function getCached(url) {
  const entry = urlCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL) {
    urlCache.delete(url);
    return null;
  }
  return entry.data;
}

function setCache(url, data) {
  urlCache.set(url, { data, timestamp: Date.now() });
}

// ===============================
// 先搜索 URLScan 有没有现成结果
// ===============================
async function searchExisting(url) {
  try {
    const encoded = encodeURIComponent(url);
    const res = await fetch(`https://urlscan.io/api/v1/search/?q=page.url:"${encoded}"&size=1`, {
      headers: { "API-Key": URLSCAN_API }
    });
    const data = await res.json();
    if (data.results && data.results.length > 0) {
      const result = data.results[0];
      const stats = result.stats || {};
      return {
        stats,
        malicious: (stats.malicious || 0) > 0,
        analysisId: result.task?.uuid,
        fromCache: true
      };
    }
  } catch (e) {
    console.warn("[urlscan] Search failed:", e.message);
  }
  return null;
}

app.post("/api/urlscan", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  // 1️⃣ 检查内存 cache
  const cached = getCached(url);
  if (cached) {
    console.log("[Cache] Hit:", url);
    return res.json({ ...cached, fromCache: true });
  }

  // 2️⃣ 搜索 URLScan 现有结果（不用重新 scan）
  const existing = await searchExisting(url);
  if (existing) {
    console.log("[URLScan] Found existing result:", url);
    setCache(url, existing);
    return res.json(existing);
  }

  // 3️⃣ 没有才 submit 新 scan
  try {
    const submitResponse = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "API-Key": URLSCAN_API,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url, visibility: "public" }),
    });

    const submitData = await submitResponse.json();
    if (!submitData.uuid) {
      return res.status(500).json({ error: "Failed to submit URL" });
    }

    const analysisId = submitData.uuid;

    // 4️⃣ 轮询等待
    let analysisData = null;
    for (let i = 0; i < 12; i++) {
      await new Promise(resolve => setTimeout(resolve, 5000));

      const analysisResponse = await fetch(`https://urlscan.io/api/v1/result/${analysisId}/`, {
        headers: { "API-Key": URLSCAN_API },
      });

      if (analysisResponse.status === 404) {
        console.log(`[urlscan] Attempt ${i + 1}, not ready yet`);
        continue;
      }

      analysisData = await analysisResponse.json();
      console.log(`[urlscan] Attempt ${i + 1}, got result`);
      break;
    }

    const stats = analysisData?.stats || {};
    const malicious = (stats.malicious || 0) > 0;

    const result = { stats, malicious, analysisId };

    // 5️⃣ 存入 cache
    setCache(url, result);
    res.json(result);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to scan URL" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 URLScan backend running on port ${PORT}`);
});
