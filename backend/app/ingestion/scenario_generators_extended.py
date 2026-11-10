"""
Extended Financial Crime Scenario Generators (`backend/app/ingestion/scenario_generators_extended.py`).
Generates realistic, labeled synthetic financial crime subgraphs across all specialized
typology families for stress-testing, automated regression, and RuleForge calibration.
"""
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple


class ExtendedCrimeScenarioFactory:
    """Factory generating synthetic multi-hop transaction topologies with ground-truth labels."""

    def __init__(self, base_timestamp: str = '2026-10-01T00:00:00Z', seed: int = 42) -> None:
        self.base_dt = datetime.fromisoformat(base_timestamp.replace('Z', '+00:00'))
        self.rng = random.Random(seed)

    def generate_tbml_overinvoicing_chain(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-TBML-001 (SCENARIO_TBML_OVERINVOICE)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(25000.0, 48000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-TBML-001-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_INTERNATIONAL',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'US',
                'destination_country': 'AE',
                'remittance_purpose': 'OVER-INVOICED SEMICONDUCTOR COMPONENT BATCH (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_TBML_OVERINVOICE',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_tbml_underinvoicing_chain(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-TBML-002 (SCENARIO_TBML_UNDERINVOICE)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(18000.0, 32000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-TBML-002-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_INTERNATIONAL',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'VG',
                'destination_country': 'US',
                'remittance_purpose': 'UNDER-INVOICED HEAVY MACHINERY SHIPMENT (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_TBML_UNDERINVOICE',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_maritime_dark_ais_bunker_chain(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-MAR-001 (SCENARIO_MARITIME_AIS_DARK)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(35000.0, 75000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-MAR-001-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_INTERNATIONAL',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'PA',
                'destination_country': 'CY',
                'remittance_purpose': 'OFFSHORE BUNKER FUEL STS LIGHTERING (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_MARITIME_AIS_DARK',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_crypto_peel_chain_subgraph(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-CRY-001 (SCENARIO_CRYPTO_PEEL_CHAIN)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(8500.0, 16000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-CRY-001-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'CRYPTO_EXCHANGE',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'US',
                'destination_country': 'PA',
                'remittance_purpose': 'VIRTUAL ASSET PEEL CHAIN FRACTIONAL SPLIT (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_CRYPTO_PEEL_CHAIN',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_cross_chain_bridge_hop_chain(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-CRY-002 (SCENARIO_BRIDGE_ANONYMIZATION)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(12000.0, 28000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-CRY-002-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'CRYPTO_EXCHANGE',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'US',
                'destination_country': 'US',
                'remittance_purpose': 'DEFI ATOMIC SWAP BRIDGE CONVERSION (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_BRIDGE_ANONYMIZATION',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_upi_imps_mule_aggregation_ring(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-RBI-003 (SCENARIO_UPI_MULE_RING)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(4500.0, 9500.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-RBI-003-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'INTERNAL_TRANSFER',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'IN',
                'destination_country': 'IN',
                'remittance_purpose': 'P2P INSTANT PAYMENT MULE AGGREGATION (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_UPI_MULE_RING',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_lrs_split_family_remittance_chain(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-RBI-004 (SCENARIO_LRS_FAMILY_SPLIT)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(15000.0, 45000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-RBI-004-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_INTERNATIONAL',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'IN',
                'destination_country': 'US',
                'remittance_purpose': 'LRS CAPITAL ACCOUNT OVERSEAS TRANSFER (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_LRS_FAMILY_SPLIT',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_fiu_sub_pan_cash_structuring_burst(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-RBI-001 (SCENARIO_SUB_PAN_STRUCTURING)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(550.0, 590.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-RBI-001-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'CASH_DEPOSIT',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'IN',
                'destination_country': 'IN',
                'remittance_purpose': 'SUB-PAN CASH DEPOSIT BRANCH FUNNEL (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_SUB_PAN_STRUCTURING',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_eu_amld6_high_risk_corridor_chain(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-EUK-001 (SCENARIO_AMLD6_HIGH_RISK_THIRD_COUNTRY)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(22000.0, 55000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-EUK-001-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_INTERNATIONAL',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'DE',
                'destination_country': 'IR',
                'remittance_purpose': '6AMLD HIGH-RISK THIRD-COUNTRY REMITTANCE (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_AMLD6_HIGH_RISK_THIRD_COUNTRY',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_uk_app_scam_coercion_drain(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-EUK-002 (SCENARIO_APP_SCAM_DRAIN)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(12000.0, 38000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-EUK-002-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_DOMESTIC',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'GB',
                'destination_country': 'GB',
                'remittance_purpose': 'FASTER PAYMENTS AUTHORIZED PUSH PAYMENT DRAIN (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_APP_SCAM_DRAIN',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_bec_vendor_routing_change_drain(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating FRD-SYN-001 (SCENARIO_BEC_SUPPLY_CHAIN)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(45000.0, 95000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-FRD-SYN-001-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_INTERNATIONAL',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'US',
                'destination_country': 'HK',
                'remittance_purpose': 'URGENT UPDATED VENDOR INVOICE SETTLEMENT (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_BEC_SUPPLY_CHAIN',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_pig_butchering_romance_drain_loop(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating FRD-SYN-002 (SCENARIO_PIG_BUTCHERING_DRAIN)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(15000.0, 48000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-FRD-SYN-002-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_INTERNATIONAL',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'US',
                'destination_country': 'SG',
                'remittance_purpose': 'OFFSHORE CRYPTO ASSET INVESTMENT PLATFORM (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_PIG_BUTCHERING_DRAIN',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_synthetic_credit_bustout_burst(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating FRD-SYN-003 (SCENARIO_SYNTHETIC_BUSTOUT)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(18000.0, 42000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-FRD-SYN-003-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_DOMESTIC',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'US',
                'destination_country': 'US',
                'remittance_purpose': 'COMMERCIAL LINE MAX UTILIZATION CASH-OUT (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_SYNTHETIC_BUSTOUT',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_reverse_factoring_phantom_invoice_chain(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-TRD-001 (SCENARIO_FACTORING_FRAUD)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(28000.0, 65000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-TRD-001-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'ACH_CREDIT',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'US',
                'destination_country': 'US',
                'remittance_purpose': 'REVERSE FACTORING PHANTOM SUPPLY INVOICE (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_FACTORING_FRAUD',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs


    def generate_lombard_loan_collateral_repayment_loop(
        self,
        source_account_id: str,
        target_account_id: str,
        customer_id: str,
        hop_count: int = 4,
        interval_hours: int = 12,
    ) -> List[Dict[str, Any]]:
        """Generates synthetic transactions demonstrating AML-WTH-001 (SCENARIO_LOMBARD_LOAN_LAUNDERING)."""
        txs: List[Dict[str, Any]] = []
        curr_dt = self.base_dt
        curr_acct = source_account_id
        for hop in range(hop_count):
            tx_id = f'tx-ext-{uuid.uuid4().hex[:10]}'
            amt = round(self.rng.uniform(50000.0, 120000.0), 2)
            next_acct = target_account_id if hop == hop_count - 1 else f'acct-hop-{hop+1}'
            txs.append({
                'id': tx_id,
                'external_tx_id': f'EXT-AML-WTH-001-{hop+1}-{uuid.uuid4().hex[:6].upper()}',
                'account_id': curr_acct,
                'customer_id': customer_id,
                'counterparty_id': None,
                'counterparty_account_id': next_acct,
                'tx_timestamp': curr_dt.isoformat(),
                'tx_type': 'WIRE_INTERNATIONAL',
                'direction': 'OUTBOUND',
                'amount_original': amt,
                'currency_original': 'USD',
                'fx_rate_to_usd': 1.0,
                'amount_usd': amt,
                'balance_after_usd': 25000.0,
                'channel': 'SWIFT_NET',
                'origin_country': 'CH',
                'destination_country': 'US',
                'remittance_purpose': 'LOMBARD CREDIT FACILITY OFFSHORE REPAYMENT (HOP {hop+1})',
                'scenario_tag': 'SCENARIO_LOMBARD_LOAN_LAUNDERING',
                'is_flagged': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            curr_dt += timedelta(hours=interval_hours)
            curr_acct = next_acct
        return txs
