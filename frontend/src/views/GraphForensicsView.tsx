import React, { useEffect, useState } from "react";
import { SentinelGraphApiClient } from "../services/apiClient";
import { EgoNetworkResponse, GraphNode } from "../types/domain";

export interface GraphForensicsViewProps {
  apiClient: SentinelGraphApiClient;
  initialCenterId?: string;
}

export const GraphForensicsView: React.FC<GraphForensicsViewProps> = ({
  apiClient,
  initialCenterId = "acct-006",
}) => {
  const [centerId, setCenterId] = useState<string>(initialCenterId);
  const [hops, setHops] = useState<number>(3);
  const [egoData, setEgoData] = useState<EgoNetworkResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const traceNetwork = async () => {
    const res = await apiClient.fetchEgoGraph(centerId, hops);
    setEgoData(res);
    if (res.nodes.length > 0) {
      setSelectedNode(res.nodes[0]);
    }
  };

  useEffect(() => {
    void traceNetwork();
  }, []);

  return (
    <div className="sg-graph-studio">
      <div className="sg-graph-toolbar">
        <input
          value={centerId}
          onChange={(e) => setCenterId(e.target.value)}
          placeholder="Account or Customer ID (e.g. acct-006)"
        />
        <select value={hops} onChange={(e) => setHops(Number(e.target.value))}>
          <option value={1}>1 Hop</option>
          <option value={2}>2 Hops</option>
          <option value={3}>3 Hops</option>
          <option value={4}>4 Hops</option>
        </select>
        <button onClick={() => void traceNetwork()}>Trace Multi-Hop Graph</button>
      </div>

      {egoData && (
        <div className="sg-graph-summary">
          <span>Center: <strong>{egoData.center_id}</strong></span>
          <span>Nodes: <strong>{egoData.node_count}</strong></span>
          <span>Edges: <strong>{egoData.edge_count}</strong></span>
        </div>
      )}

      {selectedNode && (
        <aside className="sg-node-inspector">
          <h3>Node Inspector: {selectedNode.label}</h3>
          <p>Type: {selectedNode.node_type}</p>
          <p>Risk Score: {selectedNode.risk_score}</p>
          <p>PageRank Centrality: {selectedNode.pagerank.toFixed(5)}</p>
          <pre>{JSON.stringify(selectedNode.metadata, null, 2)}</pre>
        </aside>
      )}
    </div>
  );
};
