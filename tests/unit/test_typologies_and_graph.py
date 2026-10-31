"""
Unit tests verifying the 25 AML/Fraud Typology Detectors across Families A, B, C, D, and E
plus the Multi-Hop Graph Forensics Engine (K-Hop Ego Network, Temporal Paths, Tarjan SCC, PageRank).
"""
import unittest

from backend.app.db.connection import DatabaseManager
from backend.app.graph.engine import GraphForensicsEngine
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.typologies.engine import TypologyEngine


class TypologiesAndGraphUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = DatabaseManager(":memory:")
        SyntheticCrimeSeeder(cls.db).seed_all()
        cls.typology_engine = TypologyEngine(cls.db)
        cls.graph_engine = GraphForensicsEngine(cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.db.close()

    def test_all_25_rules_registered_in_catalog(self) -> None:
        self.assertEqual(len(self.typology_engine.detectors), 25)
        ctx = self.typology_engine.build_context()
        triggered_rules = set()
        for rule_id, detector in self.typology_engine.detectors.items():
            triggers = detector.evaluate(ctx)
            if triggers:
                triggered_rules.add(rule_id)

        # Verify that our seeded synthetic crime topologies trigger across all 5 typology families
        for expected_rule in (
            "AML-STR-001",
            "AML-STR-002",
            "AML-STR-003",
            "AML-STR-004",
            "AML-STR-005",
            "AML-LAY-001",
            "AML-LAY-002",
            "AML-LAY-003",
            "AML-LAY-004",
            "AML-LAY-005",
            "AML-NET-001",
            "AML-NET-002",
            "AML-NET-003",
            "AML-NET-004",
            "AML-NET-005",
            "AML-GEO-001",
            "AML-GEO-002",
            "AML-GEO-003",
            "AML-GEO-004",
            "AML-GEO-005",
            "FRD-BEH-001",
            "FRD-BEH-002",
            "FRD-BEH-003",
            "FRD-BEH-004",
            "FRD-BEH-005",
        ):
            self.assertIn(expected_rule, triggered_rules, f"Expected typology rule {expected_rule} to trigger on seeded corpus")

    def test_tarjan_scc_and_carousel_ring_detection(self) -> None:
        rings = self.graph_engine.detect_criminal_network_rings()
        sccs = rings["strongly_connected_rings"]
        self.assertGreaterEqual(len(sccs), 1)
        # Verify carousel ring acct-003, acct-004, acct-005 is captured in an SCC
        flat_scc_nodes = {node for comp in sccs for node in comp}
        self.assertTrue({"acct-003", "acct-004", "acct-005"}.issubset(flat_scc_nodes))

        # Verify shared hardware device cluster DEV-FP-MULE-RING-991A is captured
        dev_clusters = rings["shared_device_clusters"]
        self.assertTrue(any(c["attribute_value"] == "DEV-FP-MULE-RING-991A" for c in dev_clusters))

    def test_temporal_flow_pathfinding_and_ego_subgraph(self) -> None:
        paths = self.graph_engine.find_temporal_flow_paths("acct-003", "acct-005", max_hops=4)
        self.assertGreaterEqual(len(paths), 1)
        self.assertIn("acct-004", paths[0]["account_chain"])

        ego = self.graph_engine.get_ego_network("acct-006", hops=2)
        self.assertEqual(ego["center_id"], "acct-006")
        self.assertGreater(ego["node_count"], 4)
        self.assertGreater(ego["edge_count"], 4)


if __name__ == "__main__":
    unittest.main()
