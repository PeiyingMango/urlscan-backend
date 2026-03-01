import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;
const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;

if (!URLSCAN_API_KEY) {
  console.error("⚠️ URLSCAN_API_KEY not set in environment variables!");
  process.exit(1);
}

app.use(cors());
app.use(express.json());

app.post("/api/urlscan", async (req, res) => {
  const { url } = req.body;

  if (!url) return res.status(400).json({ error: "URL is required" });

  try {
    const response = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to scan URL" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 urlscan backend running on port ${PORT}`);
});