# Extracted Statistics
The statistics is extracted for each flow and divided into client, server and flow side. This statistics are the same extracted by Tstat.

## Client/Server side
All these statistics is available for the client (c) side and for the server side (s).

 - `{client,server}_ip`: Ip used in the flow
 - `{client,server}_port`: TCP port used in the flow
 - `{c,s}_packets`: Number of the packets sent by the client/server
 - `{c,s}_flag_R`: Number of packets with RST flag enabled
 - `{c,s}_flag_A`: Number of packets with ACK flag enabled
 - `{c,s}_pureAck`: Number of segments with ACK field set to 1 and no data
 - `{c,s}_data_byte_uniq`: Total number of bytes sent in the payload
 - `{c,s}_data_pkts`: Number of packets with payload
 - `{c,s}_data_byte`: Total number of bytes transmitted in the payload, including retransmissions
 - `{c,s}_rexmit_pkts`: Number of retransmitted packets
 - `{c,s}_rexmit_bytes`: Total number of bytes into the retransmitted packets
 - `{c,s}_out_of_seq_pkts`: Number of packets out of sequence received
 - `{c,s}_flag_S`: Number of packets with SYN flag enabled
 - `{c,s}_flag_F`: Number of packets with FIN flag enabled


## Flow
 - `first_time_abs`: Absolute time of the first flow packet
 - `last_time_abs`: Absolute time of the last flow packet
 - `completation_time`: Duration of the flow since first packet to last packet
 - `{C,S}_first_payload`: Time of first packet with payload since the first one
 - `{C,S}_last_payload`: Time of first packet with payload since the last one
 - `{C,S}_first_ack`: Time of first packet with ACK since the first one
 - `rtt_{c,s}_avg`: Average value of RTTs
 - `rtt_{c,s}_min`: Min value of RTTs
 - `rtt_{c,s}_max`: Max value of RTTs
 - `rtt_{c,s}_std`: Standar deviation value of RTTs
 - `rtt_{c,s}_cnt`: Count of valid RTTs
 - `{c,s}_ttl_min`: Min value of TTL
 - `{c,s}_ttl_max`: Max value of TTL

# Extended field
Extend the total statistics extracted by Tstat, this section can be improved at any time due to the high cutomization, everyone can add statistics and create new feature for the dataset.

## Client/Server side
 - `flag_P`: Number of packets with PSH flag enabled
 - `flag_U`: Number of packets with URG flag enabled
 - `flag_E`: Number of packets with ECE flag enabled
 - `flag_C`: Number of packets with CWR flag enabled
 - `flag_N`: Number of packets with NS flag enabled

## Flow
At the moment this part is empty, you can help me to create different statistics from this part.