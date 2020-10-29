from scapy.plist import defaultdict, PacketList

def session_double_extractor(p):
    """Extract sessions from packets"""
    if 'Ether' in p:
        if 'IP' in p or 'IPv6' in p:
            ip_src_fmt = "{IP:%IP.src%}{IPv6:%IPv6.src%}"
            ip_dst_fmt = "{IP:%IP.dst%}{IPv6:%IPv6.dst%}"
            addr_fmt_1 = (ip_src_fmt, ip_dst_fmt)
            addr_fmt_2 = (ip_dst_fmt, ip_src_fmt)
            if 'TCP' in p:
                fmt_1 = "TCP {}:%r,TCP.sport% > {}:%r,TCP.dport%"
                fmt_2 = "TCP {}:%r,TCP.dport% > {}:%r,TCP.sport%"
                return p.sprintf(fmt_1.format(*addr_fmt_1)), p.sprintf(fmt_2.format(*addr_fmt_2))
    return None, None


def session_extractor(p):
    """Extract sessions from packets"""
    if 'Ether' in p:
        if 'IP' in p or 'IPv6' in p:
            ip_src_fmt = "{IP:%IP.src%}{IPv6:%IPv6.src%}"
            ip_dst_fmt = "{IP:%IP.dst%}{IPv6:%IPv6.dst%}"
            addr_fmt = (ip_src_fmt, ip_dst_fmt)
            if 'TCP' in p:
                fmt = "TCP {}:%r,TCP.sport% > {}:%r,TCP.dport%"
                return p.sprintf(fmt.format(*addr_fmt))
    return None

class MyPacketList(PacketList):
    def my_statistic_sessions(self, last_plist):
        sessions = defaultdict(self.__class__)
        
        last_session_name = []
        for p in last_plist:
            sess1, sess2 = session_double_extractor(self._elt2pkt(p))
            if sess1 and sess2:
                last_session_name += [ sess1, sess2 ]

        for p in self.res:
            sess = session_extractor(self._elt2pkt(p))
            if sess and sess in last_session_name:
                sessions[sess].append(p)
        return dict(sessions)
