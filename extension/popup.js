document.getElementById("checkBtn").addEventListener("click", async () => {
  const url = document.getElementById("urlInput").value.trim();
  const resultDiv = document.getElementById("result");

  if (!url) return;

  resultDiv.textContent = "Analyzing...";

  try {
    const response = await fetch("http://127.0.0.1:8000/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

   const statusText = !data.evaluated
  ? "⬜ NOT EVALUATED"
  : data.is_phishing
  ? "⚠️ MALICIOUS / PHISHING"
  : "✅ LEGITIMATE";
const statusColor = !data.evaluated ? "#94a3b8" : data.is_phishing ? "#f87171" : "#4ade80";
    const reasonsList = data.reasons.map((r) => `<li>${r}</li>`).join("");

    resultDiv.innerHTML = `
      <p style="color:${statusColor}; font-weight:bold;">${statusText}</p>
      <p>Threat Score: ${(data.confidence * 100).toFixed(1)}%</p>
      <ul style="padding-left: 18px; font-size: 12px;">${reasonsList}</ul>
    `;
  } catch (err) {
    resultDiv.textContent = "Error: could not reach the backend. Is it running?";
  }
});