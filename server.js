import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;
const URLSCAN_API = process.env.VIRUSTOTAL_API;
const GROQ_API_KEY = process.env.GROQ_API_KEY; // 在 Render 加这个环境变量

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
    website_address: page?.domain || null,
    last_analysis:   task?.time   || null,
    detection_counts: {
      malicious:  0,
      suspicious: 0,
      harmless:   0,
      undetected: 0,
    },
    malicious: verdicts.overall.malicious,
    verdict:  verdictsRaw?.overall?.score || 0,
    verdicts: verdicts,
    domain_registration: page?.domainCreated || null,
    domain_info: {
      domain:         page?.domain          || null,
      registrar:      page?.domainRegistrar || null,
      tls_issuer:     page?.tlsIssuer       || null,
      tls_valid_days: page?.tlsValidDays    || null,
    },
    ip_address: page?.ip || ips[0] || null,
    all_ips:    ips,
    asn:      page?.asn  || asns[0] || null,
    all_asns: asns,
    server_location: geoip?.country_name || page?.country || countries[0] || null,
    city:            geoip?.city         || null,
    region:          geoip?.region       || null,
    latitude:        geoip?.ll?.[0]      || null,
    longitude:       geoip?.ll?.[1]      || null,
    reverse_dns: page?.ptr || null,
    page_url:   page?.url   || null,
    page_title: page?.title || null,
    countries:  countries,
  };
}

// ===============================
// 搜索 URLScan 现有结果
// ===============================
async function searchExisting(url) {
  let domain = null;
  try { domain = new URL(url.startsWith("http") ? url : "https://" + url).hostname; } catch(e) {}

  const queries = [
    `page.url:"${url}"`,
    domain ? `domain:${domain}` : null,
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

  const cached = getCached(url);
  if (cached) {
    return res.json({ ...cached, fromCache: true });
  }

  const existing = await searchExisting(url);
  if (existing) {
    console.log("[URLScan] Found existing result:", url);
    setCache(url, existing);
    return res.json(existing);
  }

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

// ===============================
// AI Screenshot Analysis (Groq Vision)
// 改用 Groq llama-4-scout 替代 Gemini
// 在 Render 设置环境变量: GROQ_API_KEY
// 获取免费 key: https://console.groq.com/keys
// ===============================
app.post("/api/analyze-screenshot", async (req, res) => {
  // 支持两种调用方式:
  // 1. { screenshot_url: "https://..." }  — 从 URL 下载图片（URLScan 截图）
  // 2. { screenshot_base64: "..." }        — 直接传 base64（Extension 截图）
  const { screenshot_url, screenshot_base64 } = req.body;

  if (!screenshot_url && !screenshot_base64) {
    return res.status(400).json({ error: "screenshot_url or screenshot_base64 is required" });
  }

  if (!GROQ_API_KEY) {
    console.warn("[AI] GROQ_API_KEY not set — skipping analysis");
    return res.status(503).json({ error: "AI analysis not configured" });
  }

  try {
    let base64Image;

    if (screenshot_base64) {
      // 直接用传进来的 base64
      base64Image = screenshot_base64.replace(/^data:image\/\w+;base64,/, "");
    } else {
      // 从 URL 下载图片
      const imgRes = await fetch(screenshot_url);
      if (!imgRes.ok) {
        return res.status(400).json({ error: "Could not fetch screenshot" });
      }
      const imgBuffer = await imgRes.arrayBuffer();
      base64Image = Buffer.from(imgBuffer).toString("base64");
    }

    const prompt = `You are a cybersecurity analyst specializing in phishing detection.
Analyze this website screenshot and identify suspicious UI elements.

Respond ONLY with valid JSON in this exact format (no markdown, no explanation):
{
  "fake_logo": true or false,
  "fake_login": true or false,
  "brand_detected": "brand name if impersonating a known brand, or null",
  "urgency_detected": true or false,
  "suspicious_form": true or false,
  "overall_risk": "high" or "medium" or "low",
  "reasons": ["reason 1", "reason 2"]
}

Check for:
- Fake or copied logos from well-known brands (Google, Facebook, PayPal, banks, crypto wallets, etc.)
- Login forms asking for passwords, seed phrases, private keys, or credit cards
- Urgency messages ("Your account will be suspended", "Claim now", etc.)
- Brand impersonation (site looks like a real company but URL does not match)
- Suspicious form fields collecting sensitive data`;

    // 调用 Groq Vision API
    const groqRes = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${GROQ_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "meta-llama/llama-4-scout-17b-16e-instruct",
        max_tokens: 512,
        messages: [{
          role: "user",
          content: [
            { type: "text", text: prompt },
            {
              type: "image_url",
              image_url: {
                url: `data:image/png;base64,${base64Image}`
              }
            }
          ]
        }]
      })
    });

    if (!groqRes.ok) {
      const err = await groqRes.text();
      console.error("[AI] Groq API error:", groqRes.status, err);
      return res.status(502).json({ error: "Groq API failed", detail: err });
    }

    const groqData = await groqRes.json();
    const rawText = groqData?.choices?.[0]?.message?.content || "";

    // 解析 JSON 结果
    let parsed = null;
    try {
      const cleaned = rawText.replace(/```json|```/g, "").trim();
      parsed = JSON.parse(cleaned);
    } catch (e) {
      console.warn("[AI] Could not parse Groq response:", rawText);
      return res.status(502).json({ error: "Could not parse AI response", raw: rawText });
    }

    console.log("[AI] Groq analysis complete:", {
      fake_logo:  parsed.fake_logo,
      fake_login: parsed.fake_login,
      brand:      parsed.brand_detected,
      risk:       parsed.overall_risk,
    });

    res.json({
      fake_logo:        parsed.fake_logo        || false,
      fake_login:       parsed.fake_login       || false,
      brand_detected:   parsed.brand_detected   || null,
      urgency_detected: parsed.urgency_detected || false,
      suspicious_form:  parsed.suspicious_form  || false,
      overall_risk:     parsed.overall_risk     || "low",
      reasons:          parsed.reasons          || [],
    });

  } catch (err) {
    console.error("[AI] analyze-screenshot error:", err);
    res.status(500).json({ error: "Internal server error", detail: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 URLScan + Groq AI backend running on port ${PORT}`);
});
