import React, { useState } from "react";
import { SentinelGraphApiClient } from "../services/apiClient";
import { ShadowSimulationReport } from "../types/domain";

export interface RuleForgeStudioViewProps {
  apiClient: SentinelGraphApiClient;
}

export const RuleForgeStudioView: React.FC<RuleForgeStudioViewProps> = ({
  apiClient,
}) => {
  const [ruleId, setRuleId] = useState<string>("AML-STR-001");
  const [candidateJson, setCandidateJson] = useState<string>(
    JSON.stringify(
      {
        min_amount_usd: 7800.0,
        max_amount_usd: 9999.99,
        min_occurrences: 2,
        window_hours: 168,
      },
      null,
      2
    )
  );
  const [report, setReport] = useState<ShadowSimulationReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const executeSimulation = async () => {
    setError(null);
    try {
      const parsed = JSON.parse(candidateJson) as Record<string, unknown>;
      const sim = await apiClient.runShadowBacktest(
        ruleId,
        parsed,
        "RuleForge Studio UI shadow evaluation"
      );
      setReport(sim);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed");
    }
  };

  return (
    <div className="sg-ruleforge-studio">
      <h2>RuleForge Shadow-Mode Backtesting & Sensitivity Studio</h2>
      <div className="sg-form-group">
        <label>Target Typology Rule ID:</label>
        <input value={ruleId} onChange={(e) => setRuleId(e.target.value)} />
      </div>
      <div className="sg-form-group">
        <label>Candidate Threshold Parameters (JSON):</label>
        <textarea
          rows={6}
          value={candidateJson}
          onChange={(e) => setCandidateJson(e.target.value)}
        />
      </div>
      <button onClick={() => void executeSimulation()}>
        Run Shadow-Mode Backtest
      </button>

      {error && <div className="sg-error-banner">{error}</div>}

      {report && (
        <div className="sg-simulation-results">
          <h3>Simulation Run: {report.run_ref}</h3>
          <div className="sg-metrics-row">
            <div>Precision: {(report.precision_score * 100).toFixed(1)}%</div>
            <div>Recall: {(report.recall_score * 100).toFixed(1)}%</div>
            <div>F1 Score: {(report.f1_score * 100).toFixed(1)}%</div>
            <div>Volume Delta: {report.alert_volume_delta_pct}%</div>
            <div>Analyst Hours Saved: {report.estimated_hours_saved}h</div>
          </div>
        </div>
      )}
    </div>
  );
};
