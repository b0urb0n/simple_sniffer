import socket
import struct
import sys


HEADER_FORMAT = "({ip[proto_str]}) {ip[sip]}:{proto[sport]} -> {ip[dip]}:{proto[dport]} -- length:{data_length}"
IGNORE_PORTS = [22]
PROTCOLS = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


def main():
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
  while True:
    packet = get_and_parse_packet(s)
    if packet_is_valid(packet):
      print(HEADER_FORMAT.format(**packet))

def packet_is_valid(packet):
  if packet['proto']['sport'] in IGNORE_PORTS:
    return False
  if packet['proto']['dport'] in IGNORE_PORTS:
    return False
  if packet['data_length'] <= 0:
    return False
  return True

def get_and_parse_packet(sock):
  p_info = {'ip': {}, 'proto': {}}
  packet = sock.recvfrom(65565)[0]
  
  # IP Header
  p_info['ip']['header_raw'] = packet[0:20]
  p_info['ip']['header'] = get_ip_header(packet)
  p_info['ip']['proto'] = p_info['ip']['header'][6]
  p_info['ip']['proto_str'] = PROTCOLS[p_info['ip']['proto']]
  p_info['ip']['sip'] = socket.inet_ntoa(p_info['ip']['header'][8]);
  p_info['ip']['dip'] = socket.inet_ntoa(p_info['ip']['header'][9]);

  ip_header_length = p_info['ip']['header'][0] & 0xF
  proto_offset = ip_header_length * 4

  # Protocol header
  p_info['proto']['header_raw'] = packet[proto_offset:proto_offset+20]
  p_info['proto']['header'] = get_proto_header(packet, proto_offset) 
  p_info['proto']['sport'] = p_info['proto']['header'][0]
  p_info['proto']['dport'] = p_info['proto']['header'][1]
  
  doff_reserved = p_info['proto']['header'][4]
  proto_header_length = doff_reserved >> 4
  full_header_size = proto_offset + proto_header_length * 4
  
  # Payload
  p_info['data'] = packet[full_header_size:]
  p_info['data_length'] = len(p_info['data'])

  return p_info

def get_ip_header(packet):
  return struct.unpack('!BBHHHBBH4s4s', packet[0:20])

def get_proto_header(packet, offset):
  return struct.unpack('!HHLLBBHHH' , packet[offset:offset+20])

if __name__ == '__main__':
  main()
