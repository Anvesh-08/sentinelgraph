"""
Unified 100-Rule Global Typology Registry combining the 25 Core SentinelGraph Detectors
with the 75 Specialized Regional & Domain Typology Detectors:
- Core 25 Detectors (Structuring, Layering, Mule Networks, Geographic, Behavioral/ATO)
- 15 TBML & Correspondent Banking Detectors (`pack_tbml_correspondent`)
- 15 Crypto, DeFi & VASP Forensics Detectors (`pack_crypto_defi_forensics`)
- 15 India RBI Master Direction & FIU-IND PMLA Detectors (`pack_india_rbi_fiu_ind`)
- 15 EU AMLD6, UK FCA/PSR & MAS Notice 626 Detectors (`pack_eu_uk_apac_regimes`)
- 15 Cybercrime, BEC, Synthetic Identity & Capital Markets Detectors (`pack_cyber_bec_market_fraud`)
"""
from typing import Dict, List, Type

from backend.app.typologies.base import BaseTypologyDetector
from backend.app.typologies.catalog import FULL_100_TYPOLOGY_RULES
from backend.app.typologies.engine import ALL_DETECTOR_CLASSES
from backend.app.typologies.pack_crypto_defi_forensics import PACK_DETECTORS as CRYPTO_DETECTORS
from backend.app.typologies.pack_cyber_bec_market_fraud import PACK_DETECTORS as CYBER_DETECTORS
from backend.app.typologies.pack_eu_uk_apac_regimes import PACK_DETECTORS as EU_UK_APAC_DETECTORS
from backend.app.typologies.pack_india_rbi_fiu_ind import PACK_DETECTORS as RBI_DETECTORS
from backend.app.typologies.pack_tbml_correspondent import PACK_DETECTORS as TBML_DETECTORS


ALL_100_DETECTOR_CLASSES: List[Type[BaseTypologyDetector]] = (
    list(ALL_DETECTOR_CLASSES)
    + list(TBML_DETECTORS)
    + list(CRYPTO_DETECTORS)
    + list(RBI_DETECTORS)
    + list(EU_UK_APAC_DETECTORS)
    + list(CYBER_DETECTORS)
)


def get_100_detector_map() -> Dict[str, BaseTypologyDetector]:
    return {cls.rule_id: cls() for cls in ALL_100_DETECTOR_CLASSES}


def get_full_100_catalog() -> list:
    return FULL_100_TYPOLOGY_RULES


ALL_220_DETECTOR_CLASSES = (
    list(ALL_175_DETECTOR_CLASSES)
    + list(DEFI_DETECTORS)
    + list(INSURANCE_DETECTORS)
    + list(MARKETS_DETECTORS)
)

def get_220_detector_map():
    return {cls.rule_id: cls() for cls in ALL_220_DETECTOR_CLASSES}

def get_full_220_catalog():
    return get_full_175_catalog() + ADVANCED_TYPOLOGY_RULES
