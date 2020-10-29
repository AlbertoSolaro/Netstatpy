from netstatpy.lib.statistic_functions import *

""" 
    Config file that bind function and a name of the statistic.
    There are two functions: 
        1. statistics_single_channel() for the statics of a channel 
        2. statistics_dual_channel() for the statistics of entire flow
"""

def statistics_single_channel(session):
    flags = flags_stats(session)
    n_bytes = n_byte_stats(session)
    oos = n_oos_stats(session)

    return {
        "packets":             n_packs(session),               # Total packet
        "flag_S":              flags[0]['S'],                  # Total SYN received
        "flag_A":              flags[0]['A'],                  # Total ACK received
        "flag_R":              flags[0]['R'],                  # Total RST received
        "flag_F":              flags[0]['F'],                  # Total FIN received
        "flag_P":              flags[0]['P'],                  # Total PSH received
        "flag_U":              flags[0]['U'],                  # Total URG received
        "flag_E":              flags[0]['E'],                  # Total ECE received
        "flag_C":              flags[0]['C'],                  # Total CWR received
        "flag_N":              flags[0]['N'],                  # Total NS received
        "pureAck":             flags[1],                       # Number of Pure Ack (ACK + 0 data)
        "data_byte_uniq":      n_bytes[1],                     # Sum of payload bytes of TCP
        "data_pkts":           n_bytes[2],                     # Number of segments with payload
        "data_byte":           n_bytes[0],                     # Sum of payload bytes of TCP with retrasmission
        "rexmit_pkts":         n_retrasmitted_pkts(session),   # Retrasmission packets
        "rexmit_bytes":        n_retrasmitted_byte(session),   # Number of retransmitted bytes
        "out_of_seq_pkts":     oos[0],                         # Number of out of sequence
        "has_RST":             has_RST(flags[0]['R']),         # Check if have RST flag
        "duplicate":           check_dup_ack(session),         # Number of sequence duplicate,
        "out_seq_pkts":        oos[1],                         # Number of segments observed out of sequence
    }

def statistics_dual_channel(dual_session):
    rtt_c = rtt(dual_session, 'client', 'server')
    rtt_s = rtt(dual_session, 'server', 'client')
    first_stats_s = first_side_stats(dual_session, 'server')
    first_stats_c = first_side_stats(dual_session, 'server')
    ttl_c = ttl_stats(dual_session, 'client')
    ttl_s = ttl_stats(dual_session, 'server')

    return {
        "c_internal":           c_internal(dual_session),
        "s_internal":           s_internal(dual_session),
        # ---------------
        "first_time_abs":       first_time_abs(dual_session),
        "last_time_abs":        last_time_abs(dual_session),
        "completation_time":    completation_time(dual_session),
        # --------------
        "S_first_payload":      first_stats_s[0],
        "S_last_payload":       last_side_stats(dual_session, 'server'),
        "C_first_payload":      first_stats_c[0],
        "C_last_payload":       last_side_stats(dual_session, 'client'),
        "S_first_ack":          first_stats_s[1],
        "C_first_ack":          first_stats_c[1],
        # ---------------
        "c_ttl_min":            ttl_c[0],
        "c_ttl_max":            ttl_c[1],
        "s_ttl_min":            ttl_s[0],
        "s_ttl_max":            ttl_s[1],
        # ---------------
        "rtt_c_avg":            rtt_c[0],
        "rtt_c_min":            rtt_c[1],
        "rtt_c_max":            rtt_c[2],
        "rtt_c_std":            rtt_c[3],
        "rtt_c_cnt":            rtt_c[4],
        # ---------------
        "rtt_s_avg":            rtt_s[0],
        "rtt_s_min":            rtt_s[1],
        "rtt_s_max":            rtt_s[2],      
        "rtt_s_std":            rtt_s[3],
        "rtt_s_cnt":            rtt_s[4],
    }

## Helper function ##
def dual_TCP(sessions, HOST):
    """ Function that convert sessions in dual channel """
    dual = {}
    for session_name, packets in sessions.items():
        if packets[0].haslayer(TCP):
            mix = session_name[4:].split(" > ")

            if HOST in mix[0]:
                sender_and_receiver = (mix[0], mix[1])
                if not sender_and_receiver in dual.keys():
                    dual[sender_and_receiver] = {}
                dual[sender_and_receiver]["client"] = packets
                dual[sender_and_receiver]["client_ip"] = mix[0]
                dual[sender_and_receiver]["2"] = 1
            else:
                sender_and_receiver = (mix[1], mix[0])
                if not sender_and_receiver in dual.keys():
                    dual[sender_and_receiver] = {}
                dual[sender_and_receiver]["server"] = packets
                dual[sender_and_receiver]['server_ip'] = mix[0]
                dual[sender_and_receiver]["3"] = 1

    deleting_list = []
    for k, v in dual.items():
        if not "2" in v.keys() or not "3" in v.keys():
            deleting_list.append(k)
        else:
            del dual[k]["2"]
            del dual[k]["3"]

    return dual
