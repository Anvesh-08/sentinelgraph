import React, { useEffect, useState } from "react";
import { SentinelGraphApiClient } from "../services/apiClient";
import { CustomerProfile } from "../types/domain";

export interface CustomerDossierViewProps {
  apiClient: SentinelGraphApiClient;
  customerId?: string;
}

export const CustomerDossierView: React.FC<CustomerDossierViewProps> = ({
  apiClient,
  customerId = "cust-002",
}) => {
  const [customer, setCustomer] = useState<CustomerProfile | null>(null);
  const [eddDossier, setEddDossier] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    const loadDossier = async () => {
      const custRes = await fetch(`/api/v1/customers/${customerId}`);
      const custData = await custRes.json();
      setCustomer(custData.customer);

      const eddRes = await fetch(`/api/v1/customers/${customerId}/edd-dossier`);
      const eddData = await eddRes.json();
      setEddDossier(eddData);
    };
    void loadDossier();
  }, [customerId]);

  return (
    <div className="sg-customer-dossier">
      {customer && (
        <header className="sg-dossier-header">
          <h2>{customer.legal_name}</h2>
          <span className={`sg-badge sg-badge-${customer.risk_band}`}>
            {customer.risk_band} ({customer.composite_risk_score.toFixed(1)}/100)
          </span>
        </header>
      )}

      {eddDossier && (
        <div className="sg-edd-section">
          <h3>Enhanced Due Diligence (EDD) Review Matrix</h3>
          <pre>{JSON.stringify(eddDossier, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};
