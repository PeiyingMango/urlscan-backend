import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;
const URLSCAN_API = process.env.VIRUSTOTAL_API;

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
  console.log("[Cache] Hit:", url);
  return entry.data;
}

function setCache(url, data) {
  urlCache.set(url, { data, timestamp: Date.now() });
}

// ===============================
// 提取完整字段
// ===============================
function extractFields(result) {
  const page   = result?.page   || {};
  const meta   = result?.meta   || {};
  const lists  = result?.lists  || {};
  const task   = result?.task   || {};

  const ips       = lists?.ips       || [];
  const asns      = lists?.asns      || [];
  const countries = lists?.countries || [];

  const geoip = meta?.processors?.geoip?.data?.[0] || {};

  const verdictsRaw = result?.verdicts || {};
  const enginesRaw  = verdictsRaw?.engines || {};

  const verdicts = {
    overall: {
      score:     verdictsRaw?.overall?.score     ?? 0,
      malicious: verdictsRaw?.overall?.malicious ?? false,
      tags:      verdictsRaw?.overall?.tags      ?? [],
    },
    urlscan: {
      score:     verdictsRaw?.urlscan?.score     ?? 0,
      malicious: verdictsRaw?.urlscan?.malicious ?? false,
    },
    engines: {
      score:     enginesRaw?.score     ?? 0,
      malicious: enginesRaw?.malicious ?? false,
    },
  };

  return {
    // 基本信息
    website_address: page?.domain || null,
    last_analysis:   task?.time   || null,

      // detection_counts 由 VIRUSTOTAL_API 负责，URLScan 这边不提供
    detection_counts: {
      malicious:  0,
      suspicious: 0,
      harmless:   0,
      undetected: 0,
    },
    malicious: verdicts.overall.malicious,

    // Verdicts
    verdict:  verdictsRaw?.overall?.score || 0,
    verdicts: verdicts,

    // Domain
    domain_registration: page?.domainCreated || null,
    domain_info: {
      domain:         page?.domain          || null,
      registrar:      page?.domainRegistrar || null,
      tls_issuer:     page?.tlsIssuer       || null,
      tls_valid_days: page?.tlsValidDays    || null,
    },

    // IP
    ip_address: page?.ip || ips[0] || null,
    all_ips:    ips,

    // ASN
    asn:      page?.asn  || asns[0] || null,
    all_asns: asns,

    // Location
    server_location: geoip?.country_name || page?.country || countries[0] || null,
    city:            geoip?.city         || null,
    region:          geoip?.region       || null,
    latitude:        geoip?.ll?.[0]      || null,
    longitude:       geoip?.ll?.[1]      || null,

    // Reverse DNS
    reverse_dns: page?.ptr || null,

    // 其他
    page_url:   page?.url   || null,
    page_title: page?.title || null,
    countries:  countries,
  };
}

// ===============================
// 搜索 URLScan 现有结果（优先用 search API，避免重新 submit）
// ===============================
async function searchExisting(url) {
  // 尝试多个搜索策略，从精确到宽松
  let domain = null;
  try { domain = new URL(url.startsWith("http") ? url : "https://" + url).hostname; } catch(e) {}

  const queries = [
    `page.url:"${url}"`,           // 精确 URL 匹配
    domain ? `domain:${domain}` : null,  // domain 匹配（更容易找到结果）
  ].filter(Boolean);

  for (const q of queries) {
    try {
      const encoded = encodeURIComponent(q);
      const res = await fetch(`https://urlscan.io/api/v1/search/?q=${encoded}&size=1`, {
        headers: { "API-Key": URLSCAN_API }
      });
      const data = await res.json();

      if (data.results && data.results.length > 0) {
        const hit  = data.results[0];
        const uuid = hit._id;

        // result endpoint 通常比 search 快，直接拿
        const fullRes = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, {
          headers: { "API-Key": URLSCAN_API }
        });

        if (fullRes.ok) {
          const fullData = await fullRes.json();
          const extracted = extractFields(fullData);
          console.log(`[URLScan] Found existing via "${q}":`, uuid);
          return { ...extracted, analysisId: uuid, screenshot_url: `https://urlscan.io/screenshots/${uuid}.png`, fromCache: false, fromExisting: true };
        }
      }
    } catch (e) {
      console.warn("[URLScan] Search failed for query:", q, e.message);
    }
  }
  return null;
}

// ===============================
// 主 API
// ===============================
app.post("/api/virustotal", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  // 1️⃣ 内存 cache
  const cached = getCached(url);
  if (cached) {
    return res.json({ ...cached, fromCache: true });
  }

  // 2️⃣ 搜索现有结果（快）
  const existing = await searchExisting(url);
  if (existing) {
    console.log("[URLScan] Found existing result:", url);
    setCache(url, existing);
    return res.json(existing);
  }

  // 3️⃣ Submit 新 scan
  try {
    const submitRes = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "API-Key": URLSCAN_API,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url, visibility: "public" }),
    });

    const submitData = await submitRes.json();

    if (!submitData.uuid) {
      return res.status(500).json({ error: "Failed to submit URL", detail: submitData });
    }

    const uuid = submitData.uuid;
    console.log("[URLScan] Submitted, uuid:", uuid);

    // 4️⃣ 轮询等待结果（最多 45 秒，3秒一次）
    let analysisData = null;
    for (let i = 0; i < 15; i++) {
      await new Promise(resolve => setTimeout(resolve, 3000));

      const pollRes = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, {
        headers: { "API-Key": URLSCAN_API },
      });

      if (pollRes.status === 404) {
        console.log(`[URLScan] Attempt ${i + 1}, not ready yet`);
        continue;
      }

      if (pollRes.ok) {
        analysisData = await pollRes.json();
        console.log(`[URLScan] Attempt ${i + 1}, result ready`);
        break;
      }
    }

    if (!analysisData) {
      return res.status(504).json({ error: "URLScan timeout, try again later" });
    }

    // 5️⃣ 提取字段 + 存 cache
    const result = { ...extractFields(analysisData), analysisId: uuid, screenshot_url: `https://urlscan.io/screenshots/${uuid}.png`, fromCache: false, fromExisting: false };
    setCache(url, result);
    res.json(result);

  } catch (err) {
    console.error("[URLScan] Error:", err);
    res.status(500).json({ error: "Failed to scan URL" });
  }
});

// ===============================
// Cache 状态查看（debug 用）
// ===============================
app.get("/api/cache/stats", (req, res) => {
  res.json({
    cached_urls: urlCache.size,
    urls: [...urlCache.keys()]
  });
});

app.listen(PORT, () => {
  console.log(`🚀 URLScan backend running on port ${PORT}`);
});