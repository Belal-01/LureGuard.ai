"""
Feature Extractor — builds x(ip) = [f1..f8] from recent events.

⚠️  STUB — علي يكمل التنفيذ الحقيقي في Sprint 2.
"""
import numpy as np


def extract_features(src_ip: str, events_window: list) -> np.ndarray:
    """
    Build feature vector for a given source IP over a time window.

    Args:
        src_ip: attacker IP address
        events_window: list of NormalizedEvent within last W seconds

    Returns:
        np.ndarray shape (8,) — [f1..f8] already scaled to [0,1]

    Features:
        f1: attempts           — total login attempts
        f2: failed_ratio       — failed / attempts
        f3: distinct_users     — unique usernames tried
        f4: burst_max          — max attempts in any 10s sub-window
        f5: mean_inter_ms      — mean inter-attempt interval (ms)
        f6: stddev_inter_ms    — std dev of inter-attempt interval
        f7: hour_weight        — 0 (night) → 1 (day)
        f8: is_known_good      — 1 if IP is in whitelist
    """
    # TODO: implement in Sprint 2
    return np.zeros(8, dtype=np.float32)
