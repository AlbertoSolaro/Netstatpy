# Netstatpy 
An analysis tool for network packets, written in **Python**, that extract statistics doing _Shallow Packet Inspection_ (SPI). This software for the moment work only with packets that have a TCP header. This tool is mainly based on Scapy (https://scapy.net/) a Python library that work with raw networks packet and wrap libpcap to work with BPF.

Netstatpy is inspired from Tstat (http://tstat.polito.it/), a C software that extract network statistics, but it can do also Deep Packet Inspection (DPI) and is a little be hard to modify. As the main goal Netstatpy want to emulate the same behaviour.

## Requirements
This tool support only **Python3**, at the moment the only version tested is _3.7_. 
Dependences are store in the requirements file, the library used is:

 - numpy
 - netaddr
 - scapy
 - pandas

To install automatically use in the main folder:
```
pip3 install -r requirements.txt
```

## Feature
This tool can be used like a stand alone cli software or like a library for a Python script.

Statistics extracted from a TCP packet where collect for the client side, the server side and for the full flow. At the moment the main statistics is counter of some field in header and some average on the connection. The full statistics is in the **docs** folder.

## Usage
The software can be used stand alone with this command:

```
python -m netstatpy -h
```

This command show this helper:

```
python -m netstatpy [-h] [-p PCAP_FILE] [-o [OUTPUT_FILE]] [-t[THREAD]] [-s STEP] [--live] IP_HOST

Netstatpy: Analysis extractor for TCP traffic.

positional arguments:
  IP_HOST           interface's ip of the host that made the capture

optional arguments:
  -h, --help        show this help message and exit
  -p PCAP_FILE      in live mode is used for save the session, in normal mode
                    is used to get the session from file.
  -o [OUTPUT_FILE]  print stats in a file. OUTPUT_FILE is optional. 
                    Default if OUTPUT_FILE is ommitted pcap_%Y%m%d%H%M%S.pcap
  -t [THREAD]       numbers of thread used, ignored if live analysis. If
                    missing: single thread -- Default: cores - 3
  -s STEP           step used for the analysis. Default: 5
  --live            live analysis [enable live mode]
```