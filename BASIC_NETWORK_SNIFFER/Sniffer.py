import socket
import struct
import textwrap
from colorama import Fore, Style, init
init()
import sys
from datetime import datetime

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def print_prog_name():
	print(Fore.MAGENTA + """
███████╗██╗     ██████╗  █████╗ ████████╗██████╗ ██╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔════╝██║     ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██║████╗  ██║██║   ██║████╗ ████║
█████╗  ██║     ██████╔╝███████║   ██║   ██████╔╝██║██╔██╗ ██║██║   ██║██╔████╔██║
██╔══╝  ██║     ██╔═══╝ ██╔══██║   ██║   ██╔══██╗██║██║╚██╗██║██║   ██║██║╚██╔╝██║
███████╗███████╗██║     ██║  ██║   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
""")
	print(Fore.BLUE + """
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

def get_backup_filename():
	now = datetime.now()
	timestamp = now.strftime("%Y%m%d_%H%M%S")
	return f"sniffer_backup_{timestamp}.txt"

def get_time_now():
	now = datetime.now()
	timestamp = now.strftime("%Y%m%d_%H%M%S")
	return timestamp


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



class DualOutput:
    def __init__(self, file):
        self.file = file
        self.stdout = sys.stdout

    def write(self, message):
        self.stdout.write(message)
        self.file.write(message)

    def flush(self):
        self.stdout.flush()
        self.file.flush()

def print_strings(strings):
	print_prog_name()
	print(Style.RESET_ALL + "\nEnter a specific packet type you want to sniff, or type 'all' to sniff all:\n")
	print(Fore.YELLOW + "Supported Protocls :")
	for string in strings:
		print(Fore.GREEN + string)
	print(Style.RESET_ALL + "\n---------------------------------------------------------------------------\n")

def get_protocol_number(protocol_name):
	protocol_mapping = {
		"ICMP": 1,
		"TCP": 6,
		"UDP": 17,
		"HTTP": 80,
		"FTP": 21,
		"SMTP": 25,
		"HTTPS": 443,
		"SSH": 22,
		"SCTP": 132,
		"DNS": 53,
		"BGP": 179,
		"DHCP": 67,
		"IGMP": 2,
		"IGRP": 9,
		"GRE": 47,
		"ESP": 50,
		"AH": 51,
		"SKIP": 75,
		"EIGRP": 88,
		"OSPF": 89,
		"ALL": 0
	}
	return protocol_mapping.get(protocol_name.upper(), 404)

def main():
	try:
		backup_file = get_backup_filename()
		file = None
		dual_output = None
		protoclos = ["ICMP", "TCP", "UDP", "HTTP", "FTP", "SMTP", "HTTPS", "SSH", "SCTP", "DNS", "BGP", "DHCP", "IGMP", "IGRP", "GRE", "ESP", "AH", "SKIP", "EIGRP", "OSPF"]
		print_strings(protoclos);
		user_input = input("=>")
		protonumb = get_protocol_number(user_input)
		if protonumb == 404:
			print(Fore.RED + "Protocol not recognized.")
			sys.exit(1)
		file = open(backup_file, 'w')
		dual_output = DualOutput(file)
		sys.stdout = dual_output
		
		print("Program is running at [ " + get_time_now() + " ]")

		while True:
			cnx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
			while True:
				raw_data, _ = cnx.recvfrom(65536)
				dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
				print(Fore.MAGENTA + '\nEthernet Frame:')
				print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
					# version, headerlen, ttl, proto, src, target, payload = ipv4_packet(data)
					# print('Version: {}, Header_len: {}, ttl: {}, Protocol: {}, SRC: {}, Target: {}'.format(version, headerlen, ttl, proto, src, target))
				if eth_proto == 8:
					version, headerlen, ttl, proto, src, target, data = ipv4_packet(data)
					print(TAB_1 + Fore.YELLOW + 'IPv4 Packet:')
					print(TAB_2 + Fore.BLUE + 'Version: {}, Header Length: {}, TTL: {}'.format(version, headerlen, ttl))
					print(TAB_2 + Fore.BLUE + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

					if proto == 1 and (proto == protonumb or protonumb == 0):
						icmp_type, code, checksum, payload = icmp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'ICMP Packet:')
						print(TAB_2 + Fore.BLUE + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 6 and (proto == protonumb or protonumb == 0):
						src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload = tcp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'TCP Segment:')
						print(TAB_2 + Fore.BLUE + 'SRC Port: {}, DST Port: {}'.format(src_port, dest_port))
						print(TAB_2 + Fore.BLUE + 'Sequence: {}, Acknowledgement: {}'.format(sequence, ack))
						print(TAB_2 + Fore.BLUE + 'Flags:')
						print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 17 and (proto == protonumb or protonumb == 0):
						src_port, dest_port, length, checksum, payload = udp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'UDP Segment:')
						print(TAB_2 + Fore.BLUE + 'SRC Port: {}, DST Port: {}'.format(src_port, dest_port))
						print(TAB_2 + Fore.BLUE + 'Length: {}, Checksum: {}'.format(length, checksum))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto in [80, 21, 25]:
						message = http_ftp_smtp_message(data)
						if proto == 80 and (proto == protonumb or protonumb == 0):
							print(TAB_1 + Fore.YELLOW + 'HTTP Message:')
						elif proto == 21 and (proto == protonumb or protonumb == 0):
							print(TAB_1 + Fore.YELLOW + 'FTP Message:')
						elif proto == 25 and (proto == protonumb or protonumb == 0):
							print(TAB_1 + Fore.YELLOW + 'SMTP Message:')
						print(TAB_2 + Fore.BLUE + 'Message:')
						print(DATA_TAB_3 + Fore.GREEN + message)

					elif proto == 443 and (proto == protonumb or protonumb == 0):
						message = https_message(data)
						print(TAB_1 + Fore.YELLOW + 'HTTPS Message:')
						print(DATA_TAB_3 + Fore.GREEN + message)

					elif proto == 22 and (proto == protonumb or protonumb == 0):
						message = ssh_message(data)
						print(TAB_1 + Fore.YELLOW + 'SSH Message:')
						print(DATA_TAB_3 + Fore.GREEN + message)

					elif proto == 132 and (proto == protonumb or protonumb == 0):
						src_port, dest_port, verification_tag, checksum, payload = sctp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'SCTP Segment:')
						print(TAB_2 + Fore.BLUE + 'SRC Port: {}, DST Port: {}'.format(src_port, dest_port))
						print(TAB_2 + Fore.BLUE + 'Verification Tag: {}, Checksum: {}'.format(verification_tag, checksum))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 53 and (proto == protonumb or protonumb == 0):
						transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs, payload = dns_segment(data)
						print(TAB_1 + Fore.YELLOW + 'DNS Packet:')
						print(TAB_2 + Fore.BLUE + 'Transaction ID: {}, Flags: {}'.format(transaction_id, flags))
						print(TAB_2 + Fore.BLUE + 'Questions: {}, Answer RRs: {}'.format(questions, answer_rrs))
						print(TAB_2 + Fore.BLUE + 'Authority RRs: {}, Additional RRs: {}'.format(authority_rrs, additional_rrs))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 179 and (proto == protonumb or protonumb == 0):
						marker, length, message_type, payload = bgp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'BGP Segment:')
						print(TAB_2 + Fore.BLUE + 'Marker: {}, Length: {}, Message Type: {}'.format(marker, length, message_type))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 67 and (proto == protonumb or protonumb == 0):
						op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, payload = dhcp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'DHCP Packet:')
						print(TAB_2 + Fore.BLUE + 'Operation: {}, Hardware Type: {}, Hardware Length: {}'.format(op, htype, hlen))
						print(TAB_2 + Fore.BLUE + 'XID: {}, Seconds: {}, Flags: {}'.format(xid, secs, flags))
						print(TAB_2 + Fore.BLUE + 'Client IP: {}, Your IP: {}, Server IP: {}, Gateway IP: {}'.format(ciaddr, yiaddr, siaddr, giaddr))
						print(TAB_2 + Fore.BLUE + 'Client Hardware Address: {}'.format(chaddr))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 2 and (proto == protonumb or protonumb == 0):
						igmp_type, max_resp_time, checksum, group_address, payload = igmp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'IGMP Packet:')
						print(TAB_2 + Fore.BLUE + 'Type: {}, Max Response Time: {}, Checksum: {}'.format(igmp_type, max_resp_time, checksum))
						print(TAB_2 + Fore.BLUE + 'Group Address: {}'.format(group_address))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 9 and (proto == protonumb or protonumb == 0):
						version, opcode, edition, as_number, hold_time, in_count, out_count, checksum, payload = igrp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'IGRP Packet:')
						print(TAB_2 + Fore.BLUE + 'Version: {}, Opcode: {}'.format(version, opcode))
						print(TAB_2 + Fore.BLUE + 'AS Number: {}, Hold Time: {}, In Count: {}, Out Count: {}'.format(as_number, hold_time, in_count, out_count))
						print(TAB_2 + Fore.BLUE + 'Checksum: {}'.format(checksum))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 47:
						flags_version, protocol_type, payload = gre_segment(data)
						print(TAB_1 + Fore.YELLOW + 'GRE Packet:')
						print(TAB_2 + Fore.BLUE + 'Flags/Version: {}, Protocol Type: {}'.format(flags_version, protocol_type))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 50 and (proto == protonumb or protonumb == 0):
						spi, seq_number, payload = esp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'ESP Packet:')
						print(TAB_2 + Fore.BLUE + 'SPI: {}, Sequence Number: {}'.format(spi, seq_number))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))
				
					elif proto == 51 and (proto == protonumb or protonumb == 0):
						next_header, payload_len, spi, seq_number, payload = ah_segment(data)
						print(TAB_1 + Fore.YELLOW + 'AH Packet:')
						print(TAB_2 + Fore.BLUE + 'Next Header: {}, Payload Length: {}'.format(next_header, payload_len))
						print(TAB_2 + Fore.BLUE + 'SPI: {}, Sequence Number: {}'.format(spi, seq_number))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 57 and (proto == protonumb or protonumb == 0):
						header_type, flags, key_id, spi, payload = skip_segment(data)
						print(TAB_1 + Fore.YELLOW + 'SKIP Packet:')
						print(TAB_2 + Fore.BLUE + 'Header Type: {}, Flags: {}'.format(header_type, flags))
						print(TAB_2 + Fore.BLUE + 'Key ID: {}, SPI: {}'.format(key_id, spi))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 88 and (proto == protonumb or protonumb == 0):
						version, opcode, checksum, flags, seq_number, ack_number, payload = eigrp_segment(data)
						print(TAB_1 + Fore.YELLOW + 'EIGRP Packet:')
						print(TAB_2 + Fore.BLUE + 'Version: {}, Opcode: {}'.format(version, opcode))
						print(TAB_2 + Fore.BLUE + 'Checksum: {}, Flags: {}'.format(checksum, flags))
						print(TAB_2 + Fore.BLUE + 'Sequence Number: {}, Acknowledgement Number: {}'.format(seq_number, ack_number))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

					elif proto == 89 and (proto == protonumb or protonumb == 0):
						version, type, length, router_id, area_id, checksum, auth_type, payload = ospf_segment(data)
						print(TAB_1 + Fore.YELLOW + 'OSPF Packet:')
						print(TAB_2 + Fore.BLUE + 'Version: {}, Type: {}'.format(version, type))
						print(TAB_2 + Fore.BLUE + 'Length: {}, Router ID: {}, Area ID: {}'.format(length, router_id, area_id))
						print(TAB_2 + Fore.BLUE + 'Checksum: {}, Auth Type: {}'.format(checksum, auth_type))
						print(TAB_2 + Fore.BLUE + 'Payload:')
						print(Fore.GREEN + format_multi_line(DATA_TAB_3, payload))

	except KeyboardInterrupt:
		print(Style.RESET_ALL + "\nCtrl+C detected. Exiting gracefully...")
		sys.exit(0)
	finally:
		if dual_output:
			sys.stdout = dual_output.stdout
		if file:
			file.close()

if __name__ == '__main__':
    main()
