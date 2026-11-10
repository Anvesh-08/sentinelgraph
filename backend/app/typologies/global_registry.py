"""
Unified Global Typology Registry combining:
- 25 Core SentinelGraph Detectors
- 75 Regional & Specialized Detectors (TBML, Correspondent, Crypto, India RBI/FIU-IND, EU AMLD6/UK FCA/MAS 626, Cyber/BEC)
- 75 Sector-Specific Detectors (Maritime Sanctions, Supply-Chain Finance, Private Wealth, PayFac/Acquiring, Public Sector/Elder Scams)
- 45 Advanced Detectors (DeFi Governance, Insurance Fraud, Capital Markets HFT/Spoofing)
Total: 220 Configurable Production AML & Fraud Typology Detectors.
"""
from typing import Dict, List, Type

from backend.app.typologies.base import BaseTypologyDetector
from backend.app.typologies.catalog import DEFAULT_TYPOLOGY_RULES
from backend.app.typologies.engine import ALL_DETECTOR_CLASSES
from backend.app.typologies.pack_correspondent_maritime import PACK_DETECTORS as MARITIME_DETECTORS
from backend.app.typologies.pack_crypto_defi_forensics import PACK_DETECTORS as CRYPTO_DETECTORS
from backend.app.typologies.pack_cyber_bec_market_fraud import PACK_DETECTORS as CYBER_DETECTORS
from backend.app.typologies.pack_elder_and_public_sector import PACK_DETECTORS as PUBLIC_DETECTORS
from backend.app.typologies.pack_eu_uk_apac_regimes import PACK_DETECTORS as EU_UK_APAC_DETECTORS
from backend.app.typologies.pack_india_rbi_fiu_ind import PACK_DETECTORS as RBI_DETECTORS
from backend.app.typologies.pack_merchant_acquiring_payfac import PACK_DETECTORS as PAYFAC_DETECTORS
from backend.app.typologies.pack_tbml_correspondent import PACK_DETECTORS as TBML_DETECTORS
from backend.app.typologies.pack_trade_finance_commodities import PACK_DETECTORS as TRADE_DETECTORS
from backend.app.typologies.pack_wealth_private_banking import PACK_DETECTORS as WEALTH_DETECTORS
from backend.app.typologies.pack_defi_governance_and_tokenomics import PACK_DETECTORS as DEFI_DETECTORS
from backend.app.typologies.pack_insurance_and_health_fraud import PACK_DETECTORS as INSURANCE_DETECTORS
from backend.app.typologies.pack_capital_markets_hft_and_spoofing import PACK_DETECTORS as MARKETS_DETECTORS
from backend.app.typologies.regional_catalog import REGIONAL_TYPOLOGY_RULES
from backend.app.typologies.sector_catalog import SECTOR_TYPOLOGY_RULES
from backend.app.typologies.advanced_catalog import ADVANCED_TYPOLOGY_RULES


ALL_100_DETECTOR_CLASSES: List[Type[BaseTypologyDetector]] = (
    list(ALL_DETECTOR_CLASSES)
    + list(TBML_DETECTORS)
    + list(CRYPTO_DETECTORS)
    + list(RBI_DETECTORS)
    + list(EU_UK_APAC_DETECTORS)
    + list(CYBER_DETECTORS)
)

ALL_175_DETECTOR_CLASSES: List[Type[BaseTypologyDetector]] = (
    list(ALL_100_DETECTOR_CLASSES)
    + list(MARITIME_DETECTORS)
    + list(TRADE_DETECTORS)
    + list(WEALTH_DETECTORS)
    + list(PAYFAC_DETECTORS)
    + list(PUBLIC_DETECTORS)
)

ALL_220_DETECTOR_CLASSES: List[Type[BaseTypologyDetector]] = (
    list(ALL_175_DETECTOR_CLASSES)
    + list(DEFI_DETECTORS)
    + list(INSURANCE_DETECTORS)
    + list(MARKETS_DETECTORS)
)


def get_100_detector_map() -> Dict[str, BaseTypologyDetector]:
    return {cls.rule_id: cls() for cls in ALL_100_DETECTOR_CLASSES}


def get_full_100_catalog() -> list:
    return DEFAULT_TYPOLOGY_RULES + REGIONAL_TYPOLOGY_RULES


def get_175_detector_map() -> Dict[str, BaseTypologyDetector]:
    return {cls.rule_id: cls() for cls in ALL_175_DETECTOR_CLASSES}


def get_full_175_catalog() -> list:
    return DEFAULT_TYPOLOGY_RULES + REGIONAL_TYPOLOGY_RULES + SECTOR_TYPOLOGY_RULES


def get_220_detector_map() -> Dict[str, BaseTypologyDetector]:
    return {cls.rule_id: cls() for cls in ALL_220_DETECTOR_CLASSES}


def get_full_220_catalog() -> list:
    return get_full_175_catalog() + ADVANCED_TYPOLOGY_RULES
