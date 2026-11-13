"""Data contract for the corrected CIC-IDS2017 dataset.

Single source of truth for column names, the feature set and the label taxonomy.
Every pipeline stage, the API and the tests import from here.
"""

# One CSV per weekday, captured 3-7 July 2017 at the Canadian Institute for Cybersecurity.
DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]

# Columns that *identify* a flow instead of describing its behaviour. A model trained on them
# learns shortcuts such as "172.16.0.1 is the attacker", which does not transfer to any other
# network. They are dropped during preparation.
ID_COLUMNS = ["id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp"]

RAW_LABEL = "Label"
RAW_ATTEMPTED = "Attempted Category"  # -1 = regular flow, otherwise an "attempted" attack flow

# Behavioural flow features computed by the (fixed) CICFlowMeter.
FEATURES = [
    "Dst Port", "Protocol", "Flow Duration",
    "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd RST Flags", "Bwd RST Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    "ICMP Code", "ICMP Type", "Total TCP Flow Time",
]  # fmt: skip

# Packet, byte and flag counters can never be negative.
COUNTER_FEATURES = [
    f
    for f in FEATURES
    if f.startswith(("Total", "Subflow")) or f.endswith(("Flags", "Flag Count", "Header Length"))
]

# CICFlowMeter stores these as 16-bit signed integers; long flows overflow into negative values.
OVERFLOW_FEATURES = ["Fwd Header Length", "Bwd Header Length"]

KNOWN_PROTOCOLS = {0, 1, 6, 17}  # 0 = unknown, ICMP, TCP, UDP

# Columns added during preparation
LABEL = "label"  # fine-grained attack name, e.g. "DoS Hulk"
CATEGORY = "category"  # attack family, e.g. "DoS"
TARGET = "is_attack"  # model target: 0 = benign, 1 = attack
DAY = "day"

BENIGN = "BENIGN"
BENIGN_CATEGORY = "Benign"
UNKNOWN_CATEGORY = "Unknown"


def attack_category(label: str) -> str:
    """Map a fine-grained CIC-IDS2017 label to its attack family."""
    if label == BENIGN:
        return BENIGN_CATEGORY
    if "Patator" in label:
        return "Brute Force"  # FTP-Patator, SSH-Patator
    if label.startswith("DDoS"):
        return "DDoS"  # LOIC HTTP flood from several hosts
    if label.startswith("DoS"):
        return "DoS"  # Hulk, GoldenEye, Slowloris, Slowhttptest
    if label == "Heartbleed":
        return "Heartbleed"
    if label.startswith("Web Attack"):
        return "Web Attack"  # Brute Force, XSS, SQL Injection
    if label.startswith("Infiltration"):
        return "Infiltration"
    if label in ("Botnet", "Bot"):
        return "Botnet"
    if label.lower() == "portscan":
        return "PortScan"
    return UNKNOWN_CATEGORY
