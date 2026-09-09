"""Canonical flow-feature schema shared by capture, dataset loading and training.

Keeping one shared column list means a model trained on the public dataset
(load_cicids.py) can score flows produced live from pcap capture
(capture/pcap_to_flows.py) without a column-mismatch surprise at inference time.
"""

# Features computable both from CICIDS2017 CSVs and from raw pcap capture.
# This is the feature set the classifier is actually trained on.
CORE_FLOW_FEATURES = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_length_fwd_packets",
    "total_length_bwd_packets",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "packet_length_mean",
    "packet_length_std",
    "ratio_fwd_bwd_packets",
    "ratio_fwd_bwd_bytes",
]

# Only computable from a live/raw capture (needs actual payload bytes),
# CICIDS2017's CSV export does not carry payload -> not used for the
# baseline classifier, but extracted for later modules (anomaly detection).
CAPTURE_ONLY_FEATURES = [
    "payload_entropy",
]

IDENTIFIER_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
]

LABEL_COLUMN = "label"
