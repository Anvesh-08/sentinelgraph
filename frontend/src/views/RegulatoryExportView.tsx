import React, { useState } from "react";
import { SentinelGraphApiClient } from "../services/apiClient";

export interface RegulatoryExportViewProps {
  apiClient: SentinelGraphApiClient;
  caseId?: string;
}

export const RegulatoryExportView: React.FC<RegulatoryExportViewProps> = ({
  caseId = "case-001",
}) => {
  const [selectedFormat, setSelectedFormat] = useState<string>("FINCEN_SAR_XML");
  const [exportOutput, setExportOutput] = useState<string>("");
  const [isExporting, setIsExporting] = useState<boolean>(false);

  const triggerExport = async () => {
    setIsExporting(true);
    try {
      let endpoint = `/cases/${caseId}/export-fincen-xml`;
      if (selectedFormat === "FIU_IND_STR_XML") {
        endpoint = `/cases/${caseId}/export-fiu-ind-xml`;
      }
      const res = await fetch(`/api/v1${endpoint}`);
      const data = await res.json();
      setExportOutput(data.xml_content || JSON.stringify(data, null, 2));
    } catch (err) {
      setExportOutput(err instanceof Error ? err.message : "Export failed");
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="sg-export-console">
      <h2>Regulatory Electronic Filing & XML Batch Exporter</h2>
      <div className="sg-form-row">
        <label>Target Regime / Filing Schema:</label>
        <select
          value={selectedFormat}
          onChange={(e) => setSelectedFormat(e.target.value)}
        >
          <option value="FINCEN_SAR_XML">US FinCEN BSA E-Filing XML 2.0 (SARX Form 111)</option>
          <option value="FIU_IND_STR_XML">India FIU-IND FINnet 2.0 (PMLA STR / CBWTR)</option>
          <option value="UNODC_GOAML_XML">UNODC goAML 5.0 International Standard</option>
        </select>
        <button onClick={() => void triggerExport()} disabled={isExporting}>
          {isExporting ? "Generating XML..." : "Generate Regulatory Batch XML"}
        </button>
      </div>
      <div className="sg-export-preview">
        <pre>{exportOutput || "Select a filing schema above to generate regulatory XML."}</pre>
      </div>
    </div>
  );
};
