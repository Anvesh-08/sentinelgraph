"""
Environment-driven configuration loader for SentinelGraph.
Provides deterministic local defaults while enforcing security boundaries.
"""
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Immutable application settings loaded from environment variables."""
    app_name: str
    app_version: str
    environment: str
    host: str
    port: int
    db_path: str
    log_level: str
    token_secret: str
    audit_hmac_key: str
    token_ttl_seconds: int
    pbkdf2_iterations: int
    max_graph_hops: int
    max_graph_nodes: int
    ctr_threshold_usd: float
    sar_threshold_usd: float
    high_risk_score_cutoff: float

    @classmethod
    def from_env(cls) -> "Settings":
        base_dir = Path(__file__).resolve().parents[3]
        default_db = str(base_dir / "data" / "runtime" / "sentinelgraph.db")
        return cls(
            app_name="SentinelGraph AML & Fraud Intelligence Platform",
            app_version="1.0.0",
            environment=os.getenv("SENTINELGRAPH_ENV", "development"),
            host=os.getenv("SENTINELGRAPH_HOST", "127.0.0.1"),
            port=int(os.getenv("SENTINELGRAPH_PORT", "8000")),
            db_path=os.getenv("SENTINELGRAPH_DB_PATH", default_db),
            log_level=os.getenv("SENTINELGRAPH_LOG_LEVEL", "INFO"),
            token_secret=os.getenv(
                "SENTINELGRAPH_TOKEN_SECRET",
                "sentinelgraph-dev-ephemeral-signing-key-9f8e7d6c5b4a3f2e1d0c9b8a",
            ),
            audit_hmac_key=os.getenv(
                "SENTINELGRAPH_AUDIT_HMAC_KEY",
                "sentinelgraph-dev-audit-hmac-chain-key-1a2b3c4d5e6f7a8b9c0d1e2f",
            ),
            token_ttl_seconds=int(os.getenv("SENTINELGRAPH_TOKEN_TTL_SECONDS", "28800")),
            pbkdf2_iterations=int(os.getenv("SENTINELGRAPH_PASSWORD_PBKDF2_ITERATIONS", "210000")),
            max_graph_hops=int(os.getenv("SENTINELGRAPH_MAX_GRAPH_HOPS", "6")),
            max_graph_nodes=int(os.getenv("SENTINELGRAPH_MAX_GRAPH_NODES", "500")),
            ctr_threshold_usd=float(os.getenv("SENTINELGRAPH_CTR_THRESHOLD_USD", "10000.0")),
            sar_threshold_usd=float(os.getenv("SENTINELGRAPH_SAR_THRESHOLD_USD", "5000.0")),
            high_risk_score_cutoff=float(os.getenv("SENTINELGRAPH_HIGH_RISK_SCORE_CUTOFF", "70.0")),
        )


settings = Settings.from_env()
