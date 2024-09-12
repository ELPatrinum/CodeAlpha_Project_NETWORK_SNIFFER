import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def print_prog_name():
	print("""
███████╗██╗     ██████╗  █████╗ ████████╗██████╗ ██╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔════╝██║     ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██║████╗  ██║██║   ██║████╗ ████║
█████╗  ██║     ██████╔╝███████║   ██║   ██████╔╝██║██╔██╗ ██║██║   ██║██╔████╔██║
██╔══╝  ██║     ██╔═══╝ ██╔══██║   ██║   ██╔══██╗██║██║╚██╗██║██║   ██║██║╚██╔╝██║
███████╗███████╗██║     ██║  ██║   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
""")
	print("""
┳┓┏┓┏┳┓┓ ┏┏┓┳┓┓┏┓  ┏┓┳┓┳┏┓┏┓┏┓┳┓
┃┃┣  ┃ ┃┃┃┃┃┣┫┃┫   ┗┓┃┃┃┣ ┣ ┣ ┣┫
┛┗┗┛ ┻ ┗┻┛┗┛┛┗┛┗┛  ┗┛┛┗┻┻ ┻ ┗┛┛┗
""")

def get_mac_addr(bytes_addr):
    bytes_line = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_line).upper()

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def ipv4_packet(data):
    version_Headerlen = data[0]
    version = version_Headerlen >> 4
    headerlen = (version_Headerlen & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, headerlen, ttl, proto, ipv4(src), ipv4(target), data[headerlen:]







def tcp_segment(data):
    src_port, dest_port, sequence, ack, offset_reversed_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reversed_flags >> 12) * 4
    flag_urg = (offset_reversed_flags & 32) >> 5
    flag_ack = (offset_reversed_flags & 16) >> 4
    flag_psh = (offset_reversed_flags & 8) >> 3
    flag_rst = (offset_reversed_flags & 4) >> 2
    flag_syn = (offset_reversed_flags & 2) >> 1
    flag_fin = offset_reversed_flags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', data[:8])
    return src_port, dest_port, length, checksum, data[8:]

def icmp_segment(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def http_ftp_smtp_message(data):
    return data.decode('utf-8')

def https_message(data):
    return "Encrypted Data TLS/SSL"
def ssh_message(data):
    return "Encrypted Data SSH"

def sctp_segment(data):
    src_port, dest_port, verification_tag, checksum = struct.unpack('! H H L L', data[:12])
    return src_port, dest_port, verification_tag, checksum, data[12:]

def dns_segment(data):
    transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack('! H H H H H H', data[:12])
    return transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs, data[12:]

def bgp_segment(data):
    marker, length, message_type = struct.unpack('! 16s H B', data[:19])
    return marker, length, message_type, data[19:]

def dhcp_segment(data):
    op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr = struct.unpack('! B B B B L H H 4s 4s 4s 4s 16s', data[:44])
    return op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, data[44:]

def igmp_segment(data):
    igmp_type, max_resp_time, checksum, group_address = struct.unpack('! B B H 4s', data[:8])
    return igmp_type, max_resp_time, checksum, group_address, data[8:]

def igrp_segment(data):
    version, opcode, edition, as_number, hold_time, in_count, out_count, checksum = struct.unpack('! B B H H H H H H', data[:12])
    return version, opcode, edition, as_number, hold_time, in_count, out_count, checksum, data[12:]

def gre_segment(data):
    flags_version, protocol_type = struct.unpack('! H H', data[:4])
    return flags_version, protocol_type, data[4:]

def esp_segment(data):
    spi, seq_number = struct.unpack('! L L', data[:8])
    return spi, seq_number, data[8:]

def ah_segment(data):
    next_header, payload_len, reserved, spi, seq_number = struct.unpack('! B B H L L', data[:12])
    return next_header, payload_len, spi, seq_number, data[12:]

def skip_segment(data):
    header_type, flags, key_id, spi = struct.unpack('! B B H L', data[:8])
    return header_type, flags, key_id, spi, data[8:]

def eigrp_segment(data):
    version, opcode, checksum, flags, seq_number, ack_number = struct.unpack('! B B H L L L', data[:20])
    return version, opcode, checksum, flags, seq_number, ack_number, data[20:]

def ospf_segment(data):
    version, type, length, router_id, area_id, checksum, auth_type = struct.unpack('! B B H 4s 4s H H', data[:16])
    return version, type, length, router_id, area_id, checksum, auth_type, data[16:]

def l2tp_segment(data):
    flags_version, length, tunnel_id, session_id = struct.unpack('! H H H H', data[:8])
    return flags_version, length, tunnel_id, session_id, data[8:]





def format_multi_line(prefix, string, size=80):
    size -=len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, 	size)])


def main():
	cnx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	print_prog_name()
	while True:
		raw_data, _ = cnx.recvfrom(65536)
		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
		print('\nEthernet Frame:')
		print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
		# version, headerlen, ttl, proto, src, target, payload = ipv4_packet(data)
		# print('Version: {}, Header_len: {}, ttl: {}, Protocol: {}, SRC: {}, Target: {}'.format(version, headerlen, ttl, proto, src, target))
		if eth_proto == 8:
			version, headerlen, ttl, proto, src, target, data = ipv4_packet(data)
			print(TAB_1 + 'IPv4 Packet:')
			print(TAB_2 + 'Version: {}, Header Lenght: {}, TTL: {}'.format(version, headerlen, ttl))
			print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

			if proto == 1:
				icmp_type, code, checksum, payload = icmp_segment(data)
				print(TAB_1 + 'ICMP Packet:')
				print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.foemat(icmp_type, code, checksum))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 6:
				src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload = tcp_segment(data)
				print(TAB_1 + 'TCP Segement:')
				print(TAB_2 + 'SRC Port: {}, DST Port: {}'.format(src_port, dest_port))
				print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, ack))
				print(TAB_2 + 'Flags:')
				print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 17:
				src_port, dest_port, length, checksum, payload = udp_segment(data)
				print(TAB_1 + 'UDP Segment:')
				print(TAB_2 + 'SRC Port: {}, DST Port: {}'.format(src_port, dest_port))
				print(TAB_2 + 'Length: {}, Checksum: {}'.format(length, checksum))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto in [80, 21, 25]:
				message = http_ftp_smtp_message(data)
				if proto == 80:
					print(TAB_1 + 'HTTP Message:')
				elif proto == 21:
					print(TAB_1 + 'FTP Message:')
				elif proto == 25:
					print(TAB_1 + 'SMTP Message:')
				print(TAB_2 + 'Message:')
				print(DATA_TAB_3 + message)

			elif proto == 443:
				message = https_message(data)
				print(TAB_1 + 'HTTPS Message:')
				print(DATA_TAB_3 + message)

			elif proto == 22:
				message = ssh_message(data)
				print(TAB_1 + 'SSH Message:')
				print(DATA_TAB_3 + message)

			elif proto == 132:
				src_port, dest_port, verification_tag, checksum, payload = sctp_segment(data)
				print(TAB_1 + 'SCTP Segment:')
				print(TAB_2 + 'SRC Port: {}, DST Port: {}'.format(src_port, dest_port))
				print(TAB_2 + 'Verification Tag: {}, Checksum: {}'.format(verification_tag, checksum))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 53:
				transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs, payload = dns_segment(data)
				print(TAB_1 + 'DNS Packet:')
				print(TAB_2 + 'Transaction ID: {}, Flags: {}'.format(transaction_id, flags))
				print(TAB_2 + 'Questions: {}, Answer RRs: {}'.format(questions, answer_rrs))
				print(TAB_2 + 'Authority RRs: {}, Additional RRs: {}'.format(authority_rrs, additional_rrs))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 179:
				marker, length, message_type, payload = bgp_segment(data)
				print(TAB_1 + 'BGP Segment:')
				print(TAB_2 + 'Marker: {}, Length: {}, Message Type: {}'.format(marker, length, message_type))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 67 or proto == 68:
				op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, payload = dhcp_segment(data)
				print(TAB_1 + 'DHCP Packet:')
				print(TAB_2 + 'Operation: {}, Hardware Type: {}, Hardware Length: {}'.format(op, htype, hlen))
				print(TAB_2 + 'XID: {}, Seconds: {}, Flags: {}'.format(xid, secs, flags))
				print(TAB_2 + 'Client IP: {}, Your IP: {}, Server IP: {}, Gateway IP: {}'.format(ciaddr, yiaddr, siaddr, giaddr))
				print(TAB_2 + 'Client Hardware Address: {}'.format(chaddr))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 2:
				igmp_type, max_resp_time, checksum, group_address, payload = igmp_segment(data)
				print(TAB_1 + 'IGMP Packet:')
				print(TAB_2 + 'Type: {}, Max Response Time: {}, Checksum: {}'.format(igmp_type, max_resp_time, checksum))
				print(TAB_2 + 'Group Address: {}'.format(group_address))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 9:
				version, opcode, edition, as_number, hold_time, in_count, out_count, checksum, payload = igrp_segment(data)
				print(TAB_1 + 'IGRP Packet:')
				print(TAB_2 + 'Version: {}, Opcode: {}'.format(version, opcode))
				print(TAB_2 + 'AS Number: {}, Hold Time: {}, In Count: {}, Out Count: {}'.format(as_number, hold_time, in_count, out_count))
				print(TAB_2 + 'Checksum: {}'.format(checksum))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 47:
				flags_version, protocol_type, payload = gre_segment(data)
				print(TAB_1 + 'GRE Packet:')
				print(TAB_2 + 'Flags/Version: {}, Protocol Type: {}'.format(flags_version, protocol_type))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 50:
				spi, seq_number, payload = esp_segment(data)
				print(TAB_1 + 'ESP Packet:')
				print(TAB_2 + 'SPI: {}, Sequence Number: {}'.format(spi, seq_number))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))
    
			elif proto == 51:
				next_header, payload_len, spi, seq_number, payload = ah_segment(data)
				print(TAB_1 + 'AH Packet:')
				print(TAB_2 + 'Next Header: {}, Payload Length: {}'.format(next_header, payload_len))
				print(TAB_2 + 'SPI: {}, Sequence Number: {}'.format(spi, seq_number))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 57:
				header_type, flags, key_id, spi, payload = skip_segment(data)
				print(TAB_1 + 'SKIP Packet:')
				print(TAB_2 + 'Header Type: {}, Flags: {}'.format(header_type, flags))
				print(TAB_2 + 'Key ID: {}, SPI: {}'.format(key_id, spi))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 88:
				version, opcode, checksum, flags, seq_number, ack_number, payload = eigrp_segment(data)
				print(TAB_1 + 'EIGRP Packet:')
				print(TAB_2 + 'Version: {}, Opcode: {}'.format(version, opcode))
				print(TAB_2 + 'Checksum: {}, Flags: {}'.format(checksum, flags))
				print(TAB_2 + 'Sequence Number: {}, Acknowledgement Number: {}'.format(seq_number, ack_number))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))

			elif proto == 89:
				version, type, length, router_id, area_id, checksum, auth_type, payload = ospf_segment(data)
				print(TAB_1 + 'OSPF Packet:')
				print(TAB_2 + 'Version: {}, Type: {}'.format(version, type))
				print(TAB_2 + 'Length: {}, Router ID: {}, Area ID: {}'.format(length, router_id, area_id))
				print(TAB_2 + 'Checksum: {}, Auth Type: {}'.format(checksum, auth_type))
				print(TAB_2 + 'Payload:')
				print(format_multi_line(DATA_TAB_3, payload))









if __name__ == '__main__':
    main()
