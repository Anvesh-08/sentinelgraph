import React, { useEffect, useState } from "react";
import { SentinelGraphApiClient } from "../services/apiClient";
import { TypologyAlert } from "../types/domain";

export interface AlertTriageViewProps {
  apiClient: SentinelGraphApiClient;
  onSelectCase?: (caseId: string) => void;
}

export const AlertTriageView: React.FC<AlertTriageViewProps> = ({
  apiClient,
  onSelectCase,
}) => {
  const [alerts, setAlerts] = useState<TypologyAlert[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const refreshAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const items = await apiClient.listAlerts(
        statusFilter || undefined,
        severityFilter || undefined
      );
      setAlerts(items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alerts");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refreshAlerts();
  }, [severityFilter, statusFilter]);

  return (
    <div className="sg-view-container">
      <header className="sg-view-header">
        <h2>Transaction Monitoring Alert Triage Queue</h2>
        <div className="sg-filter-bar">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            aria-label="Filter by Severity"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter by Status"
          >
            <option value="">All Statuses</option>
            <option value="NEW">NEW</option>
            <option value="IN_TRIAGE">IN_TRIAGE</option>
            <option value="ESCALATED_TO_CASE">ESCALATED_TO_CASE</option>
            <option value="DISMISSED_FALSE_POSITIVE">DISMISSED_FALSE_POSITIVE</option>
          </select>
          <button onClick={() => void refreshAlerts()} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh Queue"}
          </button>
        </div>
      </header>

      {error && <div className="sg-error-banner">{error}</div>}

      <table className="sg-data-table">
        <thead>
          <tr>
            <th>Alert Ref</th>
            <th>Rule ID & Family</th>
            <th>Subject Customer</th>
            <th>Account</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Status</th>
            <th>Forensic Trigger Narrative</th>
            <th>Case Link</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id}>
              <td><strong>{alert.alert_ref}</strong></td>
              <td>
                <div>{alert.rule_id}</div>
                <small>{alert.rule_family}</small>
              </td>
              <td>{alert.customer_name}</td>
              <td><code>{alert.account_number}</code></td>
              <td>
                <span className={`sg-badge sg-badge-${alert.severity}`}>
                  {alert.severity}
                </span>
              </td>
              <td>{alert.risk_score.toFixed(1)}%</td>
              <td>{alert.status}</td>
              <td>{alert.trigger_narrative}</td>
              <td>
                {alert.case_id && onSelectCase ? (
                  <button onClick={() => onSelectCase(alert.case_id!)}>
                    Open Case
                  </button>
                ) : (
                  <span>Unassigned</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
