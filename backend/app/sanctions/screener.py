"""
Multi-Algorithm Watchlist, Sanctions & PEP Fuzzy Screening Engine (`FR-SANC`).
Implements pure-Python string similarity and phonetic algorithms without external C extensions:
1. Jaro-Winkler Similarity (transliteration & prefix resilience)
2. Normalized Levenshtein Edit Similarity
3. Token-Set / Token-Sort Ratio (handles inverted name order: "AL-MANSOUR, TARIQ" vs "Tariq Al Mansour")
4. Soundex / Phonetic Key Matching (catches phonetic variants: "KHALID" vs "KHALED", "SERGEY" vs "SERGEI")
5. Corroborating Date-of-Birth (DOB) and Country Code boosts/penalties.
"""
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.core.exceptions import ResourceNotFoundError
from backend.app.db.connection import DatabaseManager


NON_ALPHA_RE = re.compile(r"[^A-Z0-9\s]")


def normalize_name(raw_name: str) -> str:
    """Uppercases, strips punctuation/honorifics, and collapses whitespace."""
    cleaned = NON_ALPHA_RE.sub(" ", (raw_name or "").upper())
    tokens = [
        t for t in cleaned.split()
        if t not in {"MR", "MRS", "MS", "DR", "JR", "SR", "II", "III", "LLC", "INC", "LTD", "CORP", "CO", "SA", "GMBH"}
    ]
    return " ".join(tokens)


def soundex(token: str) -> str:
    """Computes standard 4-character American Soundex code for a name token."""
    word = "".join(ch for ch in token.upper() if ch.isalpha())
    if not word:
        return "0000"
    first_letter = word[0]
    mapping = {
        "B": "1", "F": "1", "P": "1", "V": "1",
        "C": "2", "G": "2", "J": "2", "K": "2", "Q": "2", "S": "2", "X": "2", "Z": "2",
        "D": "3", "T": "3",
        "L": "4",
        "M": "5", "N": "5",
        "R": "6",
    }
    encoded: List[str] = [first_letter]
    prev_digit = mapping.get(first_letter, "0")
    for ch in word[1:]:
        digit = mapping.get(ch, "0")
        if digit != "0" and digit != prev_digit:
            encoded.append(digit)
        prev_digit = digit
        if len(encoded) == 4:
            break
    while len(encoded) < 4:
        encoded.append("0")
    return "".join(encoded[:4])


def phonetic_signature(name: str) -> Set[str]:
    norm = normalize_name(name)
    return {soundex(tok) for tok in norm.split() if len(tok) >= 2}


def levenshtein_similarity(s1: str, s2: str) -> float:
    """Computes normalized Levenshtein similarity in [0.0, 1.0]."""
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    m, n = len(s1), len(s2)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + cost)
            prev = temp
    distance = dp[n]
    return round(1.0 - (distance / max(m, n)), 4)


def jaro_winkler_similarity(s1: str, s2: str, prefix_weight: float = 0.1) -> float:
    """Computes Jaro-Winkler similarity in [0.0, 1.0]."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    match_distance = max(0, match_distance)

    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (
        (matches / len1)
        + (matches / len2)
        + ((matches - transpositions / 2.0) / matches)
    ) / 3.0

    prefix_len = 0
    for ch1, ch2 in zip(s1[:4], s2[:4]):
        if ch1 == ch2:
            prefix_len += 1
        else:
            break

    jw = jaro + prefix_len * prefix_weight * (1.0 - jaro)
    return round(min(1.0, jw), 4)


def token_set_similarity(name1: str, name2: str) -> float:
    """Order-independent token comparison handling inverted surname/given-name formats."""
    tokens1 = sorted(set(normalize_name(name1).split()))
    tokens2 = sorted(set(normalize_name(name2).split()))
    if not tokens1 or not tokens2:
        return 0.0
    common = sorted(set(tokens1).intersection(tokens2))
    sorted1 = " ".join(tokens1)
    sorted2 = " ".join(tokens2)
    common_str = " ".join(common)

    scores = [
        jaro_winkler_similarity(sorted1, sorted2),
        levenshtein_similarity(sorted1, sorted2),
    ]
    if common_str:
        # Partial subset overlap weighted by token coverage
        coverage = len(common) / max(len(tokens1), len(tokens2))
        scores.append(0.55 * coverage + 0.45 * jaro_winkler_similarity(common_str, sorted1))
    return round(max(scores), 4)


class SanctionsScreeningService:
    """Screens entities against consolidated watchlists and manages hit dispositions."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    @staticmethod
    def compute_composite_match(
        query_name: str,
        candidate_name: str,
        query_dob: Optional[str] = None,
        candidate_dob: Optional[str] = None,
        query_country: Optional[str] = None,
        candidate_country: Optional[str] = None,
    ) -> Tuple[float, Dict[str, Any]]:
        norm_q = normalize_name(query_name)
        norm_c = normalize_name(candidate_name)

        jw = jaro_winkler_similarity(norm_q, norm_c)
        lev = levenshtein_similarity(norm_q, norm_c)
        tset = token_set_similarity(norm_q, norm_c)

        phon_q = phonetic_signature(norm_q)
        phon_c = phonetic_signature(norm_c)
        phonetic_overlap = (
            len(phon_q.intersection(phon_c)) / max(1, min(len(phon_q), len(phon_c)))
            if phon_q and phon_c
            else 0.0
        )
        phonetic_match = phonetic_overlap >= 0.66

        base_name_score = max(
            0.45 * jw + 0.35 * tset + 0.20 * lev,
            0.65 * tset + 0.35 * jw,
        )
        if phonetic_match and base_name_score >= 0.68:
            base_name_score = min(1.0, base_name_score + 0.06)

        dob_match = False
        if query_dob and candidate_dob:
            if query_dob.strip() == candidate_dob.strip():
                dob_match = True
                base_name_score = min(1.0, base_name_score + 0.08)
            elif query_dob[:4] == candidate_dob[:4]:
                base_name_score = min(1.0, base_name_score + 0.03)

        country_match = False
        if query_country and candidate_country:
            if query_country.strip().upper() == candidate_country.strip().upper():
                country_match = True
                base_name_score = min(1.0, base_name_score + 0.04)

        final_score = round(min(1.0, base_name_score), 4)
        breakdown = {
            "normalized_query": norm_q,
            "normalized_candidate": norm_c,
            "jaro_winkler": jw,
            "levenshtein": lev,
            "token_set_ratio": tset,
            "phonetic_overlap": round(phonetic_overlap, 4),
            "phonetic_match": phonetic_match,
            "dob_match": dob_match,
            "country_match": country_match,
            "final_similarity": final_score,
        }
        return final_score, breakdown

    def screen_entity(
        self,
        screened_name: str,
        date_of_birth: Optional[str] = None,
        country_code: Optional[str] = None,
        customer_id: Optional[str] = None,
        min_similarity_threshold: float = 0.72,
        persist_hits: bool = True,
    ) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            entries = [
                dict(r)
                for r in conn.execute("SELECT * FROM watchlist_entries WHERE active = 1").fetchall()
            ]

        hits: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        for entry in entries:
            aliases: List[str] = json.loads(entry.get("aliases_json") or "[]")
            candidate_names = [entry["primary_name"]] + aliases

            best_score = 0.0
            best_name = entry["primary_name"]
            best_breakdown: Dict[str, Any] = {}

            for cand in candidate_names:
                score, bdown = self.compute_composite_match(
                    query_name=screened_name,
                    candidate_name=cand,
                    query_dob=date_of_birth,
                    candidate_dob=entry.get("date_of_birth"),
                    query_country=country_code,
                    candidate_country=entry.get("nationality_country"),
                )
                if score > best_score:
                    best_score = score
                    best_name = cand
                    best_breakdown = bdown

            if best_score >= min_similarity_threshold:
                hit_id = f"shit-{uuid.uuid4().hex[:12]}"
                hit_record = {
                    "id": hit_id,
                    "customer_id": customer_id,
                    "screened_name": screened_name,
                    "watchlist_entry_id": entry["id"],
                    "list_source": entry["list_source"],
                    "program_or_category": entry["program_Or_category"],
                    "primary_watchlist_name": entry["primary_name"],
                    "matched_name": best_name,
                    "similarity_score": best_score,
                    "phonetic_match": 1 if best_breakdown.get("phonetic_match") else 0,
                    "dob_match": 1 if best_breakdown.get("dob_match") else 0,
                    "country_match": 1 if best_breakdown.get("country_match") else 0,
                    "algorithm_breakdown": best_breakdown,
                    "disposition": "PENDING_REVIEW",
                    "created_at": now,
                }
                hits.append(hit_record)

                if persist_hits:
                    with self.db.connection() as conn:
                        conn.execute(
                            """
                            INSERT INTO sanctions_hits (
                                id, customer_id, screened_name, watchlist_entry_id,
                                matched_name, similarity_score, phonetic_match,
                                dob_match, country_match, algorithm_breakdown_json,
                                disposition, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_REVIEW', ?)
                            """,
                            (
                                hit_id,
                                customer_id,
                                screened_name,
                                entry["id"],
                                best_name,
                                best_score,
                                hit_record["phonetic_match"],
                                hit_record["dob_match"],
                                hit_record["country_match"],
                                json.dumps(best_breakdown, sort_keys=True),
                                now,
                            ),
                        )

        hits.sort(key=lambda h: h["similarity_score"], reverse=True)
        return hits

    def list_hits(self, disposition: Optional[str] = None) -> List[Dict[str, Any]]:
        query = """
            SELECT sh.*, w.list_source, w.primary_name AS primary_watchlist_name, w.program_Or_category AS program_or_category
            FROM sanctions_hits sh
            JOIN watchlist_entries w ON w.id = sh.watchlist_entry_id
            WHERE 1=1
        """
        params: List[Any] = []
        if disposition:
            query += " AND sh.disposition = ?"
            params.append(disposition)
        query += " ORDER BY sh.similarity_score DESC, sh.created_at DESC"
        with self.db.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        results: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["algorithm_breakdown"] = json.loads(item.pop("algorithm_breakdown_json") or "{}")
            results.append(item)
        return results

    def resolve_hit(
        self,
        hit_id: str,
        disposition: str,
        review_notes: str,
        reviewer_user_id: str,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self.db.connection() as conn:
            existing = conn.execute("SELECT * FROM sanctions_hits WHERE id = ?", (hit_id,)).fetchone()
            if not existing:
                raise ResourceNotFoundError("SanctionsHit", hit_id)
            conn.execute(
                """
                UPDATE sanctions_hits
                SET disposition = ?, review_notes = ?, reviewed_by = ?, reviewed_at = ?
                WHERE id = ?
                """,
                (disposition, review_notes, reviewer_user_id, now, hit_id),
            )
            if existing["customer_id"]:
                new_cust_status = (
                    "CONFIRMED_MATCH"
                    if disposition == "TRUE_MATCH"
                    else ("POTENTIAL_MATCH" if disposition == "POTENTIAL_MATCH_ESCALATED" else "CLEAR")
                )
                conn.execute(
                    "UPDATE customers SET sanctions_status = ?, updated_at = ? WHERE id = ?",
                    (new_cust_status, now, existing["customer_id"]),
                )
            updated = conn.execute("SELECT * FROM sanctions_hits WHERE id = ?", (hit_id,)).fetchone()
        res = dict(updated)
        res["algorithm_breakdown"] = json.loads(res.pop("algorithm_breakdown_json") or "{}")
        return res
