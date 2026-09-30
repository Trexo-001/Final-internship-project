// src/api.ts

export interface AnalysisResponse {
  url: string;
  is_phishing: boolean;
  confidence: number;
  reasons: string[];
  evaluated: boolean;
}

/**
 * Sends a URL string to the FastAPI backend for feature extraction and threat evaluation.
 * @param url The target website address to evaluate.
 */

const baseUrl = import.meta.env.VITE_BASE_URL
export async function analyzeUrl(url: string): Promise<AnalysisResponse> {
  const response = await fetch(baseUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Server returned error ${response.status}`;
    throw new Error(message);
  }

  return response.json();
}

export const scanQrCode = async (file: File): Promise<AnalysisResponse> => {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("http://127.0.0.1:8000/api/scan-qr", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || "Failed to decode QR code.");
  }

  return response.json();
};