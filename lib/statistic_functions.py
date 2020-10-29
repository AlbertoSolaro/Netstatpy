# from scapy.all import *
from scapy.layers.inet import TCP

### Helper ###
def _tcp_data_length(packet):
    from scapy.layers.inet import IP
    return packet[IP].len - (packet[IP].ihl * 4 + packet[TCP].dataofs * 4)

### Number oriented statistic ###
def n_packs(session):
    """ Return number of packets (including retrasmission) """
    return len(session)

def flags_stats(session):
    """ Return statics releted to flags: number of flags in session, number of pure ack (flag A set to 1 and no data)"""
    flags = {'S': 0, 'A': 0, 'R': 0, 'F': 0, 'P': 0, 'U': 0, 'E': 0, 'C': 0, 'N': 0}
    pureA = 0

    for packet in session:
        if "TCP" in packet:
            f = packet[TCP].flags
        else:
            continue

        flags['S'] += 1 if f.S else 0 # SYN
        flags['A'] += 1 if f.A else 0 # ACK
        flags['R'] += 1 if f.R else 0 # RST
        flags['F'] += 1 if f.F else 0 # FIN
        flags['P'] += 1 if f.P else 0 # PSH - ask to push buffered data to the receiving application
        flags['U'] += 1 if f.U else 0 # URG - has urgent pointer
        flags['E'] += 1 if f.E else 0 # ECE - if SYN == 1 sender is ECN capable else tell congestion [RFC 3168]
        flags['C'] += 1 if f.C else 0 # CWR - sender has received ECE flag for congestion [RFC 3168 | https://tools.ietf.org/html/rfc3168]
        flags['N'] += 1 if f.N else 0 # NS - ECN-nonce [RFC 3520 | https://tools.ietf.org/html/rfc3540]

        # PureACK
        w = _tcp_data_length(packet)
        pureA += 1 if f.value == 16 and w == 0 else 0
            
    return [ flags, pureA ]

def n_byte_stats(session):
    """ Return statistics releted to numbers of byte in session: number including retrasmission , unique ones and number of packet with payload """
    n_byte = 0
    n_byte_uniq = 0
    count = 0
    
    retrasmitted = _check_retransmission(session, True)
    for packet in session:
        w = _tcp_data_length(packet)
        # Total weight
        n_byte += w

        # Count of packet with weight
        count += 1 if w else 0

        # Unique bytes
        k = (packet[TCP].seq, packet[TCP].ack, packet[TCP].flags.value, w)
        n_byte_uniq += w if not (k in retrasmitted) else 0
            
    return [ n_byte, n_byte_uniq, count ]

def has_RST(flags_R=None):
    """ Return 1 if there is a packet with RST flag set """
    return flags_R > 0

def check_dup_ack(session, returning=False):
    """ Return number of duplicate packets received """
    seqs = []
    dup = {}
    count = 0 
    for packet in session:
        n = packet[TCP].seq
        if n in seqs:
            if not n in dup.keys():
                dup[n] = []
            count += 1
            dup[n].append(packet)
        else:
            seqs.append(n)
    if returning:
        return dup
    else:
        return count

def _check_retransmission(session, returning=False):
    """ Return packet retransmitted """
    packet_bucket = {}
    count = 0
    for packet in session:
        k = (packet[TCP].seq, packet[TCP].ack, packet[TCP].flags.value, _tcp_data_length(packet))
        if k in packet_bucket.keys():
            count += 1
            packet_bucket[k].append(packet)
        else:
            packet_bucket[k] = []

    retransmitted = {}
    for key, packets in packet_bucket.items():
        if len(packets) > 0:
            retransmitted[key] = packets

    if returning:
        return retransmitted
    else:
        return count

def n_retrasmitted_pkts(session):
    return _check_retransmission(session)

def n_retrasmitted_byte(session):
    """ Return number of bytes retrasmitted received """
    retx = _check_retransmission(session,True)
    n_byte = 0
    # TODO - sostituire il doppio for con retx.values()
    for seq,dpkt in retx.items():
        for pkt in dpkt:
            n_byte += _tcp_data_length(pkt)
    return n_byte

def n_oos_stats(session):
    """ Number of out of sequence packets and their bytes """
    oos = [(packet[TCP].seq, packet.time) for packet in session]
    sorted(oos, key=lambda x: x[0])
    count = 0
    n_byte = 0
    for idx in range(1,len(oos)):
        if oos[idx-1][1] > oos[idx][1]:
            count += 1
            n_byte += _tcp_data_length(oos[idx-1])
    
    return [count, n_byte]

### Time oriented statistics ###
def _time2epoch(time):
    return round(time * 1000, 3)

def first_time_abs(dual_session):
    """ Flow first packet absolute time (epoch) """
    return min([
        _time2epoch(dual_session["client"][0].time),
        _time2epoch(dual_session["server"][0].time)
    ])

def last_time_abs(dual_session):
    """ Flow last segment absolute time (epoch) """
    return max([
        _time2epoch(dual_session["client"][-1].time),
        _time2epoch(dual_session["server"][-1].time)
    ])

def completation_time(dual_session):
    """ Flow duration since first packet to last packet """
    f, l = first_time_abs(dual_session), last_time_abs(dual_session)
    return l - f

# ------ 

def first_side_stats(dual_session, side):
    """ Side first segment with payload since the first flow segment and first ACK received """
    f = first_time_abs(dual_session)
    first_payload = None
    first_ack = None
    for packet in dual_session[side]:
        if _tcp_data_length(packet) != 0:
            first_payload = _time2epoch(packet.time) - f

        if packet[TCP].flags.A and not packet[TCP].flags.S:
            first_ack = _time2epoch(packet.time) - f
        
        if first_payload and first_ack:
            return [first_payload, first_ack]
    if first_payload:
        return [first_payload, 0]
    elif first_ack:
        return [0, first_ack]
    else:
        return [0,0]

def last_side_stats(dual_session, side):
    """ Side last segment with payload since the first flow segment """
    f = first_time_abs(dual_session)
    fp = None
    for packet in dual_session[side]:
        if _tcp_data_length(packet) != 0:
            fp = packet.time
    if fp:
        return _time2epoch(fp) - f
    else:
        return 0

### IP based ###
def __ip_internal(ip):
    from netaddr import IPNetwork
    return ip in IPNetwork('10.0.0.0/8') or ip in IPNetwork('172.16.0.0/12') or ip in IPNetwork('192.168.0.0/16')

def c_internal(dual_session):
    from scapy.layers.inet import IP
    return 1 if __ip_internal(dual_session['client'][0][IP].src) else 0

def s_internal(dual_session):
    from scapy.layers.inet import IP
    return 1 if __ip_internal(dual_session['server'][0][IP].dst) else 0

### TCP e2e ###
def ttl_stats(dual_session, which):
    from scapy.layers.inet import IP
    ttls = [packet[IP].ttl for packet in dual_session[which]]
    return [ min(ttls), max(ttls) ]

### RTT ###
def rtt(dual_session,first,second):
    rtt = []
    last_idx = 0
    for packet_c in dual_session[first]:
        seq = packet_c[TCP].seq
        w = _tcp_data_length(packet_c)
        # If simply ACK packet ignore
        if packet_c[TCP].flags.value == 16 and w == 0:
            continue
        # remove_pkt = None
        for idx in range(last_idx, len(dual_session[second])):
            packet_s = dual_session[second][idx]
            if not packet_s[TCP].flags.A:
                continue
            
            ack = packet_s[TCP].ack
            if (seq + w <= ack) and ( packet_s.time * 1000 - packet_c.time * 1000 > 0):
                rtt.append( packet_s.time * 1000 - packet_c.time * 1000 )
                last_idx = idx
                break

    from numpy import std

    return [
        0 if len(rtt) < 1 else sum(rtt)/len(rtt), 
        0 if len(rtt) < 1 else round(min(rtt), 3), 
        0 if len(rtt) < 1 else round(max(rtt), 3),
        0 if len(rtt) < 2 else round(std(rtt), 3),
        len(rtt)
    ]

# TODO - Window Size
# TODO - MSS
