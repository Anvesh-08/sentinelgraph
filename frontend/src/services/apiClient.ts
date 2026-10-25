/**
 * Typed REST API client for communicating with the SentinelGraph FastAPI backend.
 */
import {
  CustomerProfile,
  EgoNetworkResponse,
  ShadowSimulationReport,
  TypologyAlert,
} from "../types/domain";

export class SentinelGraphApiClient {
  private baseUrl: string;
  private accessToken: string | null = null;

  constructor(baseUrl = "/api/v1") {
    this.baseUrl = baseUrl;
  }

  public setAccessToken(token: string): void {
    this.accessToken = token;
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(init.headers as Record<string, string>),
    };
    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers,
    });
    const payload = await response.json();
    if (!response.ok) {
      const message =
        payload?.error?.message || `HTTP ${response.status}: Request failed`;
      throw new Error(message);
    }
    return payload as T;
  }

  public async login(username: string, password: string) {
    const res = await this.request<{ access_token: string; user: Record<string, string> }>(
      "/auth/login",
      {
        method: "POST",
        body: JSON.stringify({ username, password }),
      }
    );
    this.setAccessToken(res.access_token);
    return res;
  }

  public async listAlerts(status?: string, severity?: string): Promise<TypologyAlert[]> {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (severity) params.set("severity", severity);
    const res = await this.request<{ count: number; alerts: TypologyAlert[] }>(
      `/alerts?${params.toString()}`
    );
    return res.alerts;
  }

  public async fetchEgoGraph(centerId: string, hops = 3): Promise<EgoNetworkResponse> {
    return this.request<EgoNetworkResponse>(
      `/graph/ego/${encodeURIComponent(centerId)}?hops=${hops}`
    );
  }

  public async runShadowBacktest(
    ruleId: string,
    candidateParameters: Record<string, unknown>,
    notes?: string
  ): Promise<ShadowSimulationReport> {
    return this.request<ShadowSimulationReport>("/simulations/backtest", {
      method: "POST",
      body: JSON.stringify({
        rule_id: ruleId,
        candidate_parameters: candidateParameters,
        notes,
      }),
    });
  }

  public async listCustomers(riskBand?: string): Promise<CustomerProfile[]> {
    const query = riskBand ? `?risk_band=${encodeURIComponent(riskBand)}` : "";
    const res = await this.request<{ count: number; customers: CustomerProfile[] }>(
      `/customers${query}`
    );
    return res.customers;
  }
}
