/**
 * Strongly-typed TypeScript domain contracts for the SentinelGraph Investigator Workbench.
 */

export type Role =
  | "L1_ANALYST"
  | "L2_INVESTIGATOR"
  | "QA_COMPLIANCE_OFFICER"
  | "RISK_ENGINEER"
  | "SYSTEM_ADMIN";

export type RiskBand = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type AlertSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type AlertStatus =
  | "NEW"
  | "IN_TRIAGE"
  | "ESCALATED_TO_CASE"
  | "DISMISSED_FALSE_POSITIVE";

export type CaseStatus =
  | "OPEN"
  | "IN_REVIEW_L1"
  | "ESCALATED_L2"
  | "PENDING_QA_APPROVAL"
  | "SAR_APPROVED"
  | "SAR_FILED"
  | "CLOSED_FALSE_POSITIVE"
  | "CLOSED_NO_SAR";

export interface CustomerProfile {
  id: string;
  external_ref: string;
  customer_type: "INDIVIDUAL" | "BUSINESS";
  legal_name: string;
  residence_country: string;
  occupation_or_industry: string;
  expected_monthly_volume_usd: number;
  pep_flag: number;
  adverse_media_flag: number;
  sanctions_status: "CLEAR" | "POTENTIAL_MATCH" | "CONFIRMED_MATCH";
  composite_risk_score: number;
  risk_band: RiskBand;
}

export interface TypologyAlert {
  id: string;
  alert_ref: string;
  customer_id: string;
  customer_name: string;
  account_id: string;
  account_number: string;
  rule_id: string;
  rule_name: string;
  rule_family: string;
  severity: AlertSeverity;
  risk_score: number;
  status: AlertStatus;
  trigger_narrative: string;
  evidence_metrics: Record<string, unknown>;
  case_id?: string | null;
  sla_due_at: string;
  created_at: string;
}

export interface GraphNode {
  id: string;
  node_type: "CUSTOMER" | "ACCOUNT" | "COUNTERPARTY" | "BENEFICIAL_OWNER" | "SHARED_DEVICE";
  label: string;
  risk_score: number;
  hop_distance: number;
  pagerank: number;
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  edge_type: string;
  label: string;
  amount_usd: number;
  metadata: Record<string, unknown>;
}

export interface EgoNetworkResponse {
  center_id: string;
  hops: number;
  node_count: number;
  edge_count: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ShadowSimulationReport {
  id: string;
  run_ref: string;
  rule_id: string;
  rule_name: string;
  baseline_alert_count: number;
  candidate_alert_count: number;
  confusion_matrix: {
    true_positives: number;
    false_positives: number;
    true_negatives: number;
    false_negatives: number;
  };
  precision_score: number;
  recall_score: number;
  f1_score: number;
  alert_volume_delta_pct: number;
  estimated_hours_saved: number;
}
