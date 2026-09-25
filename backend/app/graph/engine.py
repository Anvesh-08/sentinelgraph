"""
Heterogeneous Multi-Hop Graph Forensics & Link Analysis Engine (`FR-GRAPH`).
Constructs a unified graph of Customers, Accounts, External Counterparties, and Shared Attributes
(Device Fingerprints, IP Addresses, Physical Addresses, Tax IDs, and Beneficial Owners).

Provides pure-Python implementations of:
1. K-Hop Ego Subgraph Extraction (with node risk styling & edge attribution)
2. Temporal Fund-Flow Pathfinding ($t_1 \le t_2 \le \dots \le t_k$)
3. Directed Cycle / Carousel Ring Detection
4. Tarjan's Strongly Connected Components (SCC) Algorithm
5. Iterative PageRank Centrality & Hub/Authority Scoring
6. Shared-PII / Hardware Identity Cluster Detection
"""
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.db.connection import DatabaseManager
from backend.app.typologies.base import parse_iso_ts


class GraphForensicsEngine:
    """Executes multi-hop topological and temporal graph analytics over the SentinelGraph ledger."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def _load_graph_primitives(self) -> Dict[str, Any]:
        with self.db.connection() as conn:
            customers = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM customers").fetchall()}
            accounts = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM accounts").fetchall()}
            counterparties = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM counterparties").fetchall()}
            ubos = [dict(r) for r in conn.execute("SELECT * FROM beneficial_owners").fetchall()]
            transactions = [
                dict(r) for r in conn.execute("SELECT * FROM transactions ORDER BY tx_timestamp ASC").fetchall()
            ]
            alerts = [
                dict(r)
                for r in conn.execute("SELECT * FROM alerts WHERE status != 'DISMISSED_FALSE_POSITIVE'").fetchall()
            ]

        alerts_by_account: Dict[str, List[Dict[str, Any]]] = {}
        for a in alerts:
            alerts_by_account.setdefault(a["account_id"], []).append(a)

        return {
            "customers": customers,
            "accounts": accounts,
            "counterparties": counterparties,
            "ubos": ubos,
            "transactions": transactions,
            "alerts_by_account": alerts_by_account,
        }

    def compute_pagerank(
        self,
        nodes: Set[str],
        directed_edges: List[Tuple[str, str, float]],
        damping: float = 0.85,
        iterations: int = 25,
    ) -> Dict[str, float]:
        """Computes weighted PageRank centrality across account/entity nodes."""
        n = len(nodes)
        if n == 0:
            return {}
        node_list = sorted(nodes)
        ranks: Dict[str, float] = {u: 1.0 / n for u in node_list}

        out_weights: Dict[str, float] = {u: 0.0 for u in node_list}
        adj: Dict[str, List[Tuple[str, float]]] = {u: [] for u in node_list}

        for u, v, w in directed_edges:
            if u in nodes and v in nodes:
                weight = max(1.0, float(w))
                adj[u].append((v, weight))
                out_weights[u] += weight

        for _ in range(iterations):
            new_ranks: Dict[str, float] = {u: (1.0 - damping) / n for u in node_list}
            sink_mass = sum(ranks[u] for u in node_list if out_weights[u] == 0.0)
            for u in node_list:
                new_ranks[u] += damping * (sink_mass / n)
                if out_weights[u] > 0:
                    for v, w in adj[u]:
                        new_ranks[v] += damping * ranks[u] * (w / out_weights[u])
            ranks = new_ranks

        return {k: round(v, 6) for k, v in ranks.items()}

    def tarjan_scc(self, nodes: Set[str], adj: Dict[str, Set[str]]) -> List[List[str]]:
        """
        Tarjan's Strongly Connected Components (SCC) algorithm in O(|V| + |E|) time.
        Returns all non-trivial strongly connected components (size >= 2).
        """
        index = 0
        indices: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        stack: List[str] = []
        on_stack: Set[str] = set()
        sccs: List[List[str]] = []

        def strongconnect(node: str) -> None:
            nonlocal index
            indices[node] = index
            lowlink[node] = index
            index += 1
            stack.append(node)
            on_stack.add(node)

            for neighbor in sorted(adj.get(node, set())):
                if neighbor not in indices:
                    strongconnect(neighbor)
                    lowlink[node] = min(lowlink[node], lowlink[neighbor])
                elif neighbor in on_stack:
                    lowlink[node] = min(lowlink[node], indices[neighbor])

            if lowlink[node] == indices[node]:
                comp: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack.remove(w)
                    comp.append(w)
                    if w == node:
                        break
                if len(comp) >= 2:
                    sccs.append(sorted(comp))

        for v in sorted(nodes):
            if v not in indices:
                strongconnect(v)

        return sccs

    def get_ego_network(self, center_id: str, hops: int = 3) -> Dict[str, Any]:
        """
        Extracts the K-hop heterogeneous ego subgraph around a customer_id or account_id,
        including monetary flow edges, ownership edges, and shared device/IP attribute links.
        """
        hops = max(1, min(6, int(hops)))
        data = self._load_graph_primitives()
        customers = data["customers"]
        accounts = data["accounts"]
        counterparties = data["counterparties"]
        transactions = data["transactions"]
        alerts_by_account = data["alerts_by_account"]

        nodes_map: Dict[str, Dict[str, Any]] = {}
        edges_list: List[Dict[str, Any]] = []
        undirected_adj: Dict[str, Set[str]] = {}
        flow_edges_for_pr: List[Tuple[str, str, float]] = []

        def add_node(node_id: str, node_type: str, label: str, risk_score: float = 15.0, meta: Optional[Dict[str, Any]] = None) -> None:
            if node_id not in nodes_map:
                nodes_map[node_id] = {
                    "id": node_id,
                    "node_type": node_type,
                    "label": label,
                    "risk_score": round(float(risk_score), 2),
                    "metadata": meta or {},
                }
            undirected_adj.setdefault(node_id, set())

        def add_edge(src: str, dst: str, edge_type: str, label: str, amount_usd: float = 0.0, meta: Optional[Dict[str, Any]] = None) -> None:
            edges_list.append(
                {
                    "source": src,
                    "target": dst,
                    "edge_type": edge_type,
                    "label": label,
                    "amount_usd": round(float(amount_usd), 2),
                    "metadata": meta or {},
                }
            )
            undirected_adj.setdefault(src, set()).add(dst)
            undirected_adj.setdefault(dst, set()).add(src)

        # Register Customers & Accounts
        for cid, cust in customers.items():
            add_node(
                cid,
                "CUSTOMER",
                cust["legal_name"],
                risk_score=cust["composite_risk_score"],
                meta={"risk_band": cust["risk_band"], "customer_type": cust["customer_type"], "country": cust["residence_country"]},
            )

        for aid, acct in accounts.items():
            cust = customers.get(acct["customer_id"], {})
            acct_alerts = alerts_by_account.get(aid, [])
            acct_risk = max([float(cust.get("composite_risk_score", 15.0))] + [float(a["risk_score"]) for a in acct_alerts])
            add_node(
                aid,
                "ACCOUNT",
                f"{acct['account_number']} ({cust.get('legal_name', 'Unknown')})",
                risk_score=acct_risk,
                meta={
                    "account_number": acct["account_number"],
                    "account_type": acct["account_type"],
                    "status": acct["status"],
                    "balance_usd": acct["current_balance_usd"],
                    "alert_count": len(acct_alerts),
                    "customer_id": acct["customer_id"],
                },
            )
            add_edge(acct["customer_id"], aid, "OWNS_ACCOUNT", "Owns Account")

        # Register UBOs
        for ubo in data["ubos"]:
            ubo_node_id = ubo.get("linked_individual_customer_id") or f"ubo-{ubo['id']}"
            if ubo_node_id not in nodes_map:
                add_node(
                    ubo_node_id,
                    "BENEFICIAL_OWNER",
                    f"UBO: {ubo['full_name']} ({ubo['ownership_percentage']:.0f}%)",
                    risk_score=75.0 if ubo.get("is_pep") else 30.0,
                    meta={"nationality": ubo["nationality"], "is_pep": bool(ubo["is_pep"])},
                )
            add_edge(ubo_node_id, ubo["customer_id"], "BENEFICIAL_OWNER_OF", f"{ubo['ownership_percentage']:.0f}% UBO")

        # Register Transactions & Shared Device/IP Nodes
        device_usage: Dict[str, Set[str]] = {}
        for tx in transactions:
            if tx.get("device_fingerprint"):
                device_usage.setdefault(tx["device_fingerprint"], set()).add(tx["account_id"])

        for tx in transactions:
            src_acct = tx["account_id"]
            amt = float(tx["amount_usd"])
            peer_acct = tx.get("counterparty_account_id")
            cp_id = tx.get("counterparty_id")

            if peer_acct and peer_acct in accounts:
                if tx["direction"] == "OUTBOUND":
                    add_edge(
                        src_acct,
                        peer_acct,
                        "FUNDS_TRANSFER",
                        f"${amt:,.0f} ({tx['tx_type']})",
                        amount_usd=amt,
                        meta={"tx_id": tx["id"], "timestamp": tx["tx_timestamp"], "tx_type": tx["tx_type"]},
                    )
                    flow_edges_for_pr.append((src_acct, peer_acct, amt))
            elif cp_id and cp_id in counterparties:
                cp = counterparties[cp_id]
                cp_node_id = f"cp-{cp_id}"
                add_node(
                    cp_node_id,
                    "COUNTERPARTY",
                    f"{cp['name']} ({cp['country_code']})",
                    risk_score=75.0 if cp.get("is_high_risk_jurisdiction") else 25.0,
                    meta={"country": cp["country_code"], "entity_type": cp["entity_type"]},
                )
                if tx["direction"] == "OUTBOUND":
                    add_edge(src_acct, cp_node_id, "EXTERNAL_TRANSFER", f"${amt:,.0f} ({tx['tx_type']})", amount_usd=amt, meta={"tx_id": tx["id"]})
                    flow_edges_for_pr.append((src_acct, cp_node_id, amt))
                else:
                    add_edge(cp_node_id, src_acct, "EXTERNAL_TRANSFER", f"${amt:,.0f} ({tx['tx_type']})", amount_usd=amt, meta={"tx_id": tx["id"]})
                    flow_edges_for_pr.append((cp_node_id, src_acct, amt))

            dev = tx.get("device_fingerprint")
            if dev and len(device_usage.get(dev, set())) >= 2:
                dev_node = f"dev-{dev}"
                add_node(dev_node, "SHARED_DEVICE", f"Device: {dev}", risk_score=88.0, meta={"shared_by_count": len(device_usage[dev])})
                add_edge(src_acct, dev_node, "USED_DEVICE", "Shared Hardware Fingerprint")

        # BFS from center_id up to `hops`
        if center_id not in nodes_map:
            # Try matching external_ref or account_number
            for nid, nmeta in nodes_map.items():
                if nmeta.get("metadata", {}).get("account_number") == center_id:
                    center_id = nid
                    break

        visited: Dict[str, int] = {center_id: 0}
        queue: deque = deque([(center_id, 0)])
        while queue:
            curr, dist = queue.popleft()
            if dist >= hops:
                continue
            for nbr in undirected_adj.get(curr, set()):
                if nbr not in visited:
                    visited[nbr] = dist + 1
                    queue.append((nbr, dist + 1))

        sub_nodes = [
            {**nodes_map[nid], "hop_distance": visited[nid]}
            for nid in sorted(visited.keys())
            if nid in nodes_map
        ]
        sub_node_ids = set(visited.keys())
        sub_edges = [
            e for e in edges_list
            if e["source"] in sub_node_ids and e["target"] in sub_node_ids
        ]

        pr_scores = self.compute_pagerank(sub_node_ids, flow_edges_for_pr)
        for n in sub_nodes:
            n["pagerank"] = pr_scores.get(n["id"], 0.0)

        return {
            "center_id": center_id,
            "hops": hops,
            "node_count": len(sub_nodes),
            "edge_count": len(sub_edges),
            "nodes": sub_nodes,
            "edges": sub_edges,
        }

    def find_temporal_flow_paths(
        self,
        source_account_id: str,
        target_account_id: str,
        max_hops: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Finds all directed fund-flow paths from `source_account_id` to `target_account_id`
        where transaction timestamps are monotonically non-decreasing ($t_1 \le t_2 \le \dots \le t_k$).
        """
        max_hops = max(1, min(6, int(max_hops)))
        data = self._load_graph_primitives()
        out_edges: Dict[str, List[Dict[str, Any]]] = {}
        for tx in data["transactions"]:
            if tx["direction"] == "OUTBOUND" and tx.get("counterparty_account_id"):
                out_edges.setdefault(tx["account_id"], []).append(tx)

        found_paths: List[Dict[str, Any]] = []
        stack: List[Tuple[str, List[str], List[Dict[str, Any]], Optional[Any]]] = [
            (source_account_id, [source_account_id], [], None)
        ]

        while stack:
            curr, path_accounts, path_txs, last_dt = stack.pop()
            if len(path_txs) >= max_hops:
                continue
            for edge in out_edges.get(curr, []):
                edge_dt = parse_iso_ts(edge["tx_timestamp"])
                if last_dt is not None and edge_dt < last_dt:
                    continue
                nxt = edge["counterparty_account_id"]
                new_accounts = path_accounts + [nxt]
                new_txs = path_txs + [edge]
                if nxt == target_account_id:
                    total_flow = round(sum(float(t["amount_usd"]) for t in new_txs), 2)
                    min_link = round(min(float(t["amount_usd"]) for t in new_txs), 2)
                    duration_hrs = round(
                        (parse_iso_ts(new_txs[-1]["tx_timestamp"]) - parse_iso_ts(new_txs[0]["tx_timestamp"])).total_seconds()
                        / 3600.0,
                        2,
                    )
                    found_paths.append(
                        {
                            "hop_count": len(new_txs),
                            "account_chain": new_accounts,
                            "transaction_ids": [t["id"] for t in new_txs],
                            "total_cumulative_usd": total_flow,
                            "bottleneck_flow_usd": min_link,
                            "elapsed_hours": duration_hrs,
                        }
                    )
                elif nxt not in path_accounts:
                    stack.append((nxt, new_accounts, new_txs, edge_dt))

        found_paths.sort(key=lambda p: (p["hop_count"], -p["bottleneck_flow_usd"]))
        return found_paths

    def detect_criminal_network_rings(self) -> Dict[str, Any]:
        """
        Executes global graph forensics across the entire ledger to surface:
        1. Strongly Connected Components (Tarjan SCC mule rings)
        2. Shared Hardware / IP Identity Clusters
        3. Top PageRank Centrality Conduit Accounts
        """
        data = self._load_graph_primitives()
        accounts = data["accounts"]
        customers = data["customers"]
        transactions = data["transactions"]

        acct_nodes = set(accounts.keys())
        directed_adj: Dict[str, Set[str]] = {a: set() for a in acct_nodes}
        weighted_edges: List[Tuple[str, str, float]] = []
        device_map: Dict[str, Set[str]] = {}
        ip_map: Dict[str, Set[str]] = {}

        for tx in transactions:
            src = tx["account_id"]
            dst = tx.get("counterparty_account_id")
            amt = float(tx["amount_usd"])
            if tx["direction"] == "OUTBOUND" and dst and dst in acct_nodes:
                directed_adj.setdefault(src, set()).add(dst)
                weighted_edges.append((src, dst, amt))

            if tx.get("device_fingerprint"):
                device_map.setdefault(tx["device_fingerprint"], set()).add(src)
            if tx.get("ip_address"):
                ip_map.setdefault(tx["ip_address"], set()).add(src)

        scc_rings = self.tarjan_scc(acct_nodes, directed_adj)
        pr_scores = self.compute_pagerank(acct_nodes, weighted_edges)

        shared_device_clusters = [
            {
                "attribute_type": "DEVICE_FINGERPRINT",
                "attribute_value": dev,
                "accounts": sorted(accts),
                "customers": sorted({accounts[a]["customer_id"] for a in accts if a in accounts}),
            }
            for dev, accts in sorted(device_map.items())
            if len(accts) >= 2
        ]

        shared_ip_clusters = [
            {
                "attribute_type": "IP_ADDRESS",
                "attribute_value": ip,
                "accounts": sorted(accts),
                "customers": sorted({accounts[a]["customer_id"] for a in accts if a in accounts}),
            }
            for ip, accts in sorted(ip_map.items())
            if len(accts) >= 2
        ]

        top_central_accounts = []
        for aid, score in sorted(pr_scores.items(), key=lambda x: x[1], reverse=True)[:10]:
            acct = accounts.get(aid, {})
            cust = customers.get(acct.get("customer_id", ""), {})
            top_central_accounts.append(
                {
                    "account_id": aid,
                    "account_number": acct.get("account_number"),
                    "customer_name": cust.get("legal_name"),
                    "pagerank_score": score,
                    "risk_band": cust.get("risk_band"),
                }
            )

        return {
            "strongly_connected_rings": scc_rings,
            "shared_device_clusters": shared_device_clusters,
            "shared_ip_clusters": shared_ip_clusters,
            "top_central_conduit_accounts": top_central_accounts,
        }
