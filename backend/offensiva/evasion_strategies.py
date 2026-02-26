"""
Evasion strategies mapping and helpers
"""
import logging
from typing import List, Dict, Any

logger = logging.getLogger("cerberus.offensiva.evasion_strategies")


WAF_STRATEGIES = {
    "Cloudflare": [
        "use_double_encoding",
        "add_random_params",
        "slow_jitter",
        "header_variation",
        "reduce_payload_length",
    ],
    "ModSecurity": [
        "comment_injection",
        "obfuscate_operators",
        "char_encoding",
        "split_payload",
    ],
    "Akamai": [
        "time_based_jitter",
        "header_variation",
        "append_null",
    ],
    "GenericWAF": [
        "encoding_mix",
        "case_randomize",
        "add_noise_params",
    ],
    "Sucuri": ["use_hex_encoding", "comment_injection", "slow_jitter", "alternate_whitespace"],
    "Wordfence": ["case_randomization", "add_random_params", "chunk_transfer"],
    "Barracuda": ["use_double_encoding", "unicode_normalization", "slow_jitter"],
    "Fortinet": ["comment_injection", "header_variation", "reduce_payload_length"],
    "Imperva_Incapsula": ["use_double_encoding", "unicode_normalization", "alternate_methods"],
    "AWS_WAF": ["use_hex_encoding", "comment_injection", "chunk_transfer", "slow_jitter"],
    "F5_BigIP_ASM": ["use_double_encoding", "string_concatenation", "slow_jitter"],
    "Citrix_ADC": ["comment_injection", "case_randomization", "header_variation"],
}


def get_bypass_strategies(waf_name: str) -> List[str]:
    """Return ordered list of strategies for a given WAF name"""
    return WAF_STRATEGIES.get(waf_name, WAF_STRATEGIES.get("GenericWAF", []))


def apply_strategies_to_engine(engine, strategies: List[str]):
    """Apply strategy hints to an engine instance by mutating config.custom_params

    This function does not perform active bypass — it only adjusts engine parameters
    (mutation levels, headers, tamper flags) so that the scanning adapters will
    use more evasive payloads.
    """
    if not engine or not hasattr(engine, "config"):
        return

    cp = engine.config.custom_params or {}
    # Increase mutation level for payload mutators
    if "mutation_level" not in cp:
        cp["mutation_level"] = 2

    # Map strategies to config hints
    for s in strategies:
        if s == "use_double_encoding":
            cp["double_encode"] = True
        if s == "add_random_params":
            cp.setdefault("extra_params", {})
            cp["extra_params"]["cerberus_noise"] = "1"
        if s == "slow_jitter":
            cp["rate_limit_rps"] = max(1, getattr(engine.config, "rate_limit_rps", 5) // 2)
        if s == "header_variation":
            cp.setdefault("header_variations", True)
        if s == "reduce_payload_length":
            cp["max_payloads"] = min(getattr(engine.config, "max_payloads", 50), 20)
        if s == "comment_injection":
            cp["tamper_hint"] = "comment_injection"
        if s == "obfuscate_operators":
            cp["tamper_hint"] = "operator_sub"
        if s == "char_encoding":
            cp["force_char_encoding"] = True
        if s == "split_payload":
            cp["split_payload"] = True
        if s == "time_based_jitter":
            cp["time_jitter"] = True
        if s == "append_null":
            cp["append_null_byte"] = True
        if s == "encoding_mix":
            cp["encoding_mix"] = True
        if s == "case_randomize":
            cp["random_case"] = True
        if s == "add_noise_params":
            cp.setdefault("extra_params", {})
            cp["extra_params"]["n"] = "1"

    engine.config.custom_params = cp
    logger.info(f"Applied WAF strategies to engine {engine.config.engine_id}: {strategies}")
