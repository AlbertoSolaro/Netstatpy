"""
 Mapping_client, Mapping_server and Mapping_dual are the original field of tstat analysis.
 With a 0 as value, the field will not be in the scapy analysis
 Extended field are original and must be implemented in the functions_lib and mapped in test file
"""
# Structure Tstat
mapping_client = {
    "c_ip":             "client_ip",
    "c_port":           "client_port",
    "c_pkts_all":       "packets",
    "c_rst_cnt":        "flag_R",
    "c_ack_cnt":        "flag_A",
    "c_ack_cnt_p":      "pureAck",
    "c_bytes_uniq":     "data_byte_uniq",
    "c_pkts_data":      "data_pkts",
    "c_bytes_all":      "data_byte",
    "c_pkts_retx":      "rexmit_pkts",
    "c_bytes_retx":     "rexmit_bytes",
    "c_pkts_ooo":       "out_of_seq_pkts",
    "c_syn_cnt":        "flag_S",
    "c_fin_cnt":        "flag_F"
}

mapping_server = {
    "s_ip":             "server_ip",
    "s_port":           "server_port",
    "s_pkts_all":       "packets",
    "s_rst_cnt":        "flag_R",
    "s_ack_cnt":        "flag_A",
    "s_ack_cnt_p":      "pureAck",
    "s_bytes_uniq":     "data_byte_uniq",
    "s_pkts_data":      "data_pkts",
    "s_bytes_all":      "data_byte",
    "s_pkts_retx":      "rexmit_pkts",
    "s_bytes_retx":     "rexmit_bytes",
    "s_pkts_ooo":       "out_of_seq_pkts",
    "s_syn_cnt":        "flag_S",
    "s_fin_cnt":        "flag_F"
}

mapping_dual = {
    "first":            "first_time_abs",
    "last":             "last_time_abs",
    "durat":            "completation_time",
    "c_first":          "C_first_payload",
    "s_first":          "S_first_payload",
    "c_last":           "C_last_payload",
    "s_last":           "S_last_payload",

    "c_first_ack":      "C_first_ack",
    "s_first_ack":      "S_first_ack",

    "c_isint":          "c_internal",
    "s_isint":          "s_internal",

    "c_iscrypto":       0,   # skip
    "s_iscrypto":       0,   # skip
    "con_t":            0,   # skip
    "p2p_t":            0,   # skip
    "http_t":           0,   # skip
    "c_rtt_avg":        "rtt_c_avg",
    "c_rtt_min":        "rtt_c_min",
    "c_rtt_max":        "rtt_c_max",
    "c_rtt_std":        "rtt_c_std",
    "c_rtt_cnt":        "rtt_c_cnt",
    "c_ttl_min":        "c_ttl_min",
    "c_ttl_max":        "c_ttl_max",
    "s_rtt_avg":        "rtt_s_avg",
    "s_rtt_min":        "rtt_s_min",
    "s_rtt_max":        "rtt_s_max",
    "s_rtt_std":        "rtt_s_std",
    "s_rtt_cnt":        "rtt_s_cnt",
    "s_ttl_min":        "s_ttl_min",
    "s_ttl_max":        "s_ttl_max",
}

# Extended field
extend_mappig_client = {
    "c_flag_P": "flag_P",
    "c_flag_U": "flag_U",
    "c_flag_E": "flag_E",
    "c_flag_C": "flag_C",
    "c_flag_N": "flag_N",
}

extend_mappig_server = {
    "s_flag_P": "flag_P",
    "s_flag_U": "flag_U",
    "s_flag_E": "flag_E",
    "s_flag_C": "flag_C",
    "s_flag_N": "flag_N",
}

extend_mappig_dual = {

}