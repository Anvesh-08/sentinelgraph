"""
Domain reference constants for high-risk jurisdictions, offshore financial centers,
and cash-intensive or high-AML-risk industry classifications.
"""
from typing import Set

# High-risk jurisdictions subject to FATF Call for Action / strict sanctions
FATF_BLACK_LIST_COUNTRIES: Set[str] = {"KP", "IR", "MM"}

# Jurisdictions under Increased Monitoring (FATF Grey List & High-Risk Corridors)
FATF_GREY_LIST_COUNTRIES: Set[str] = {
    "SY", "YE", "SS", "HT", "VE", "LB", "CD", "MO", "BG", "BF", "CM", "HR", "KE", "ML", "MZ", "NG", "PH", "SN", "TZ", "VN", "ZA"
}

# Offshore Financial Centers / Secrecy Havens frequently used in shell-company layering
OFFSHORE_FINANCIAL_CENTERS: Set[str] = {
    "VG",  # British Virgin Islands
    "KY",  # Cayman Islands
    "PA",  # Panama
    "SC",  # Seychelles
    "BZ",  # Belize
    "BM",  # Bermuda
    "LI",  # Liechtenstein
    "MC",  # Monaco
    "VU",  # Vanuatu
    "BS",  # Bahamas
}

HIGH_RISK_CORRIDORS: Set[str] = (
    FATF_BLACK_LIST_COUNTRIES | FATF_GREY_LIST_COUNTRIES | OFFSHORE_FINANCIAL_CENTERS
)

CASH_INTENSIVE_INDUSTRIES: Set[str] = {
    "MONEY SERVICE BUSINESS",
    "MSB",
    "CURRENCY EXCHANGE",
    "CRYPTO OTC",
    "DIGITAL ASSET BROKER",
    "CASINO",
    "GAMING",
    "PRECIOUS METALS",
    "JEWELRY",
    "BULLION",
    "PAWNBROKER",
    "USED AUTO DEALER",
    "PARKING GARAGE",
    "LAUNDROMAT",
    "CONVENIENCE STORE",
    "OFFSHORE HOLDING",
    "IMPORT EXPORT GENERAL TRADING",
}
