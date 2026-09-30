import React, { useState } from "react";
import { analyzeUrl, scanQrCode } from './api';
import type { AnalysisResponse } from "./api";
import jsPDF from "jspdf";

export const App: React.FC = () => {
  const [inputUrl, setInputUrl] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const exportReport = () => {
    if (!result) return;

    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();

    doc.setFontSize(16);
    doc.text("Phishing URL Detection Report", 20, 20);

    doc.setFontSize(11);
    doc.text(`Generated: ${timestamp}`, 20, 30);

    doc.setFontSize(12);
    doc.text("Target URL:", 20, 45);
    doc.setFontSize(10);
    doc.text(doc.splitTextToSize(result.url, 170), 20, 52);

    doc.setFontSize(12);
    doc.text("Status:", 20, 70);
    doc.setFontSize(12);
    doc.text(result.is_phishing ? "MALICIOUS / PHISHING" : "LEGITIMATE", 60, 70);

    doc.text("Threat Score:", 20, 80);
    doc.text(`${(result.confidence * 100).toFixed(1)}%`, 60, 80);

    doc.setFontSize(12);
    doc.text("Reasons:", 20, 95);
    doc.setFontSize(10);
    let y = 102;
    result.reasons.forEach((reason) => {
      const lines = doc.splitTextToSize(`• ${reason}`, 170);
      doc.text(lines, 20, y);
      y += lines.length * 6;
    });

    doc.save(`phishing-report-${Date.now()}.pdf`);
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim()) return;

    const cleanUrl = inputUrl.replace(/\[(.*?)\]\(.*?\)/g, "$1").trim();

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeUrl(cleanUrl);
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: "700px", margin: "40px auto", color: "#e0e0e0", fontFamily: "sans-serif" }}>
      <h2 style={{ textAlign: "center" }}>Phishing URL Detector</h2>

      <form onSubmit={handleAnalyze} style={{ display: "flex", gap: "10px", marginBottom: "20px" }}>
        <input
          type="text"
          placeholder="https://example.com/login"
          value={inputUrl}
          onChange={(e) => setInputUrl(e.target.value)}
          style={{
            flex: 1,
            padding: "12px",
            borderRadius: "6px",
            border: "1px solid #444",
            background: "#222",
            color: "#fff",
          }}
        />
        <button
          type="submit"
          disabled={loading}
          style={{
            padding: "12px 24px",
            background: "#2563eb",
            color: "#fff",
            border: "none",
            borderRadius: "6px",
            cursor: "pointer",
            fontWeight: "bold",
          }}
        >
          {loading ? "Analyzing..." : "Check URL"}
        </button>
      </form>

      <div style={{ marginTop: "24px", padding: "20px", background: "#1e293b", borderRadius: "8px", border: "1px solid #334155" }}>
        <h3 style={{ fontSize: "16px", fontWeight: "bold", color: "#fff", marginBottom: "8px" }}>🛡️ Quishing Defense (QR Code Scanner)</h3>
        <p style={{ fontSize: "13px", color: "#94a3b8", marginBottom: "12px" }}>Upload an image of a QR code to decode its URL and analyze it for threats.</p>

        <input
          type="file"
          accept="image/*"
          style={{ color: "#94a3b8", fontSize: "14px" }}
          onChange={async (e) => {
            const file = e.target.files?.[0];
            if (!file) return;
            try {
              const data = await scanQrCode(file);
              setResult(data);
            } catch (err: any) {
              alert(err.message || "Failed to scan QR code");
            }
          }}
        />
      </div>

      {error && (
        <div style={{ padding: "12px", background: "#ef444422", border: "1px solid #ef4444", borderRadius: "6px", color: "#f87171" }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ background: "#18181b", padding: "24px", borderRadius: "8px", border: "1px solid #27272a" }}>
          <h3 style={{ textAlign: "center", marginTop: 0 }}>Analysis Summary</h3>

          <p style={{ textAlign: "center", wordBreak: "break-all" }}>
            <strong>Target URL:</strong> {result.url}
          </p>

         <p style={{ textAlign: "center", fontSize: "1.2rem", fontWeight: "bold" }}>
  Status:{" "}
  <span style={{ color: !result.evaluated ? "#94a3b8" : result.is_phishing ? "#f87171" : "#4ade80" }}>
    {!result.evaluated
      ? "⬜ NOT EVALUATED"
      : result.is_phishing
      ? "⚠️ MALICIOUS / PHISHING"
      : "✅ LEGITIMATE"}
  </span>
</p>

          <p style={{ textAlign: "center" }}>
            <strong>Threat Score:</strong> {(result.confidence * 100).toFixed(1)}%
          </p>

          <div style={{ marginTop: "20px" }}>
            <h4 style={{ color: "#93c5fd" }}>Why was this result generated? (Explainability)</h4>
            <ul style={{ background: "#27272a", padding: "15px 30px", borderRadius: "6px" }}>
              {result.reasons && result.reasons.length > 0 ? (
                result.reasons.map((reason, idx) => (
                  <li key={idx} style={{ marginBottom: "6px" }}>
                    {reason}
                  </li>
                ))
              ) : (
                <li>No specific anomalies detected.</li>
              )}
            </ul>
          </div>

          <button
            onClick={exportReport}
            style={{
              marginTop: "20px",
              padding: "10px 20px",
              background: "#16a34a",
              color: "#fff",
              border: "none",
              borderRadius: "6px",
              cursor: "pointer",
              fontWeight: "bold",
              width: "100%",
            }}
          >
            📄 Export Report as PDF
          </button>
        </div>
      )}
    </div>
  );
};

export default App;