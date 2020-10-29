#!/usr/bin/python3
from netstatpy.config import *
from netstatpy.lib import *

## CONFIG ##
DEBUG = 1 # [ 0: No debug, 1: Print statistics, 2: Print statistics and argument ]
args = None

# Global Object for the sniffing
pcap = MyPacketList()

# Thread initializer
def initializer(argsv, pcapv):
    global args
    global pcap
    args = argsv
    pcap = pcapv

# Function that calculate statistics
def calculate_statistics(index, step=1):
    global DEBUG
    global args
    global pcap

    if DEBUG > 0 :
        print("{} - Index {}".format(str(current_process()), index))

    # Find all sessions
    sessions = None
    if isinstance(pcap, MyPacketList):
        sessions = pcap[:index].my_statistic_sessions(pcap[index - step: index])
    else:
        pcap = pcap.get()
        sessions = pcap[:index].my_statistic_sessions(pcap[index - step: index])

    # Join two channels of same TCP connection
    dual_session = dual_TCP(sessions, args.IP_HOST)
    
    stats = []
    ## START ANALYSIS ##
    for name, session in dual_session.items():
        # If only one side of the flow, skip analysis
        if not ("server" in session.keys() and "client" in session.keys()):
            continue        

        if DEBUG > 0:
            print(name, str( len(session['client']) + len(session['server']) ))

        tmp_stats = {}
        tmp_stats['client'] = statistics_single_channel(session['client'])
        tmp_stats['client']['client_ip'] = session['client_ip'].split(":")[0]
        tmp_stats['client']['client_port'] = session['client_ip'].split(":")[1]

        tmp_stats['server'] = statistics_single_channel(session['server'])
        tmp_stats['server']['server_ip'] = session['server_ip'].split(":")[0]
        tmp_stats['server']['server_port'] = session['server_ip'].split(":")[1]

        tmp_stats.update(statistics_dual_channel(session))

        if DEBUG > 1:
            print(tmp_stats)

        session_stats = convert_to_list(tmp_stats)

        if args.live and args.output_file :
            write_session_log(args.output_file, session_stats)
        
        stats.append(session_stats)
    else:
        if DEBUG > 0:
            print()
            print()

    if args.export:
        return stats

# Callback function for live analysis
def sniff_cb(pkt):
    global pcap
    pcap.append(pkt)
    calculate_statistics(pcap, len(pcap))

# MAIN
def main():
    global DEBUG
    global args

    args = check_argument(DEBUG)

    if args.live:
        if args.output_file:
            write_header(args.output_file)

        # Read packets from interface
        packets = sniff(prn=sniff_cb, filter="tcp")
        wrpcap(args.pcap_file, packets)
    else:
        if args.thread == 1:
            global pcap # Don't use initializer

        # Read packets from capture
        pcap = MyPacketList(rdpcap(args.pcap_file))

        indexs = range(args.step, len(pcap), args.step)

        sessions_stats = []
        if args.thread > 1:
            manager = Manager()
            pcap_shared = manager.Value(MyPacketList, pcap)
            
            # Note: Try to optimize, first job are faster then the lastest one, leave out the 70% of total packets allow to reuse faster worker
            chunck_size = min([ int(len(indexs)/args.thread * 0.3), 2000 ])

            func = partial(calculate_statistics, step=args.step)
            with Pool(args.thread, initializer, initargs=(args, pcap_shared, )) as pool:
                sessions_stats = pool.map(func, indexs, chunck_size)
        else:
            for index in indexs:
                sessions_stats.append(calculate_statistics(index, args.step))
        stats = []
        for s in sessions_stats:
            stats += s

        # If args.output_file write out the statistics
        stats = export_list(stats, output_file=args.output_file)
        
        if args.export:
            return stats

# Wrapper for the import of the package
def Netstatpy(IP_HOST, pcap=None, output_flag=True, output_file=None, live=False, training=False):
    args = [ IP_HOST ]

    if pcap:
        args.append("-p")
        args.append(pcap)
    if output_flag:
        args.append("-o")
        if output_file:
            args.append(output_file)
    if live:
        args.append("--live")
    if training:
        args.append("--training")
        args.append("-t")

    sys.argv = [ sys.argv[0] ] + args

    if training and not live:
        return main()
    elif training and live:
        print("Sorry, but it's not possible training with live data")
    else:
        main()

# Launch MAIN
if __name__ == "__main__":
    main()
