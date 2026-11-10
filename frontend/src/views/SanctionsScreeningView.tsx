import React, { useState } from "react";
import { SentinelGraphApiClient } from "../services/apiClient";

export interface SanctionsScreeningViewProps {
  apiClient: SentinelGraphApiClient;
}

export const SanctionsScreeningView: React.FC<SanctionsScreeningViewProps> = () => {
  const [screenName, setScreenName] = useState<string>("Viktor Morozov");
  const [country, setCountry] = useState<string>("RU");
  const [results, setResults] = useState<string>("");

  const executeScreen = async () => {
    const res = await fetch("/api/v1/sanctions/screen", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        screened_name: screenName,
        country_code: country,
        min_similarity_threshold: 0.65,
      }),
    });
    const data = await res.json();
    setResults(JSON.stringify(data, null, 2));
  };

  return (
    <div className="sg-sanctions-console">
      <h2>Multi-Algorithm Watchlist & PEP Screener</h2>
      <div className="sg-input-bar">
        <input
          value={screenName}
          onChange={(e) => setScreenName(e.target.value)}
          placeholder="Entity Name"
        />
        <input
          value={country}
          onChange={(e) => setCountry(e.target.value)}
          placeholder="Country"
        />
        <button onClick={() => void executeScreen()}>Screen Watchlists</button>
      </div>
      <pre>{results || "Click screen to inspect fuzzy matches."}</pre>
    </div>
  );
};
