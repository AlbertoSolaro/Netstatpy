import sys, time, argparse, os
from datetime import datetime

def check_argument(DEBUG):
    statistics_folder = "Analysis/scapy/"
    statistics_file_name = statistics_folder + "tcp_analysis_" + \
        datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S%f')

    max_default_thread = os.cpu_count() - 3

    parser = argparse.ArgumentParser(prog="python -m netstatpy",
        description='Netstatpy: Analysis extractor for TCP traffic.')

    parser.add_argument(
        'IP_HOST', help='ip of the host that made the capture.')
    parser.add_argument('-p', dest='pcap_file',
                        help='in live mode is used for save the session, in normal mode is used to get the session.')
    parser.add_argument('-o', dest='output_file', nargs='?',
                        const=statistics_file_name, help='print stats in a file. OUTPUT_FILE is optional.')
    parser.add_argument('-t', dest='thread', nargs='?', const=max_default_thread, default=1, type=int, 
                        help='numbers of thread used, ignored if live analysis. If missing: single thread -- Default: cores - 3 ')
    parser.add_argument('-s', dest='step', default=5, help='step used for the analysis. Default: 5')
    parser.add_argument('--live', action='store_true', help='live analysis')

    # Used only if netstatpy is used like package
    parser.add_argument('--training', dest="export", action='store_true', help=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.live and not args.pcap_file:
        pcap_folder = "Catture/"
        args.pcap_file = pcap_folder + "pcap_" + \
            datetime.fromtimestamp(time.time()).strftime(
                '%Y%m%d%H%M%S') + ".pcap"

    if DEBUG > 1:
        print(args)

    return args
