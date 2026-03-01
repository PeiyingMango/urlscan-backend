const express = require("express");
const fetch = require("node-fetch");

const app = express();
app.use(express.json());

// ✅ 这里读取环境变量
const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;

app.post("/api/urlscan", async (req, res) => {
  const { url } = req.body;

  try {
    const response = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "API-Key": URLSCAN_API_KEY   // ✅ 在这里用
      },
      body: JSON.stringify({
        url: url,
        visibility: "public"
      })
    });

    const data = await response.json();
    res.json(data);

  } catch (error) {
    res.status(500).json({ error: "urlscan failed" });
  }
});

app.listen(3000);