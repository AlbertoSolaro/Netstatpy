from netstatpy.lib.myplist import MyPacketList
from netstatpy.lib.extractor import write_header, write_session_log, export_list, convert_to_list
from netstatpy.lib.functions import check_argument

# Handling import for main
import sys
from scapy.utils import rdpcap, wrpcap
from scapy.sendrecv import sniff

from functools import partial
from multiprocessing import Manager, Pool
from multiprocessing import current_process

def _fix_widows():
    from multiprocessing import set_start_method
    set_start_method('spawn', True)


_fix_widows()
