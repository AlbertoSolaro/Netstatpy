from netstatpy.lib.extractor import compair_field, read_log

tfields, ttcp_sessions = read_log("Analysis/tstat/201907260044_web_spotify.pcap.out/2019_07_26_00_43.out/log_tcp_complete")
fields, tcp_sessions = read_log("Analysis/scapy/tcp_analysis_20200112174623")

for session in tcp_sessions:
    for tsession in ttcp_sessions:
        if tsession['c_ip'] == session['c_ip'] and tsession['s_ip'] == session['s_ip'] \
            and tsession['c_port'] == session['c_port'] and tsession['s_port'] == session['s_port'] :
            print("{}:{} > {}: {}".format(session['c_ip'],session['c_port'],session['s_ip'],session['s_port']))
            compair_field(session, tsession)
            print()
            
