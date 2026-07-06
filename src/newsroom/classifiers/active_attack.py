"""Expert: active exploitation and attack campaigns."""

from newsroom.classifiers.base import KeywordClassifier, Signal


class ActiveAttackClassifier(KeywordClassifier):
    name = "active_attack"
    objective = "Detect active exploitation, campaigns, and threat-actor activity."

    signals = [
        Signal(r"active(?:ly)? exploit(?:ed|ation)|exploited in the wild|under (?:active )?attack", 0.40, "active exploitation reported"),
        Signal(r"\bcampaign\b", 0.20, "attack campaign"),
        Signal(r"\bAPT\b|state[- ]sponsored|nation[- ]state", 0.20, "advanced persistent threat actor"),
        Signal(r"\bransomware\b", 0.25, "ransomware activity"),
        Signal(r"\bmalware\b|\bbotnet\b|\btrojan\b", 0.15, "malware involved"),
        Signal(r"\bphishing\b|spear[- ]phishing", 0.15, "phishing vector"),
    ]
