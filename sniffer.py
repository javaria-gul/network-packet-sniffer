import socket
import struct
import queue
import threading
import traceback

packet_queue = queue.Queue()
stop_sniffing = threading.Event()
DEBUG = False

def get_protocol_name(proto_number):
    if proto_number == 6:
        return "TCP"
    elif proto_number == 17:
        return "UDP"
    elif proto_number == 1:
        return "ICMP"
    else:
        return f"Other({proto_number})"

def parse_ip_packet(data):
    try:
        if len(data) < 34:
            return None

        ip_header = data[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        ttl = iph[5]
        protocol_number = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])
        total_length = iph[2]

        return {
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "protocol": get_protocol_name(protocol_number),
            "ttl": ttl,
            "length": total_length,
            "protocol_number": protocol_number
        }
    except Exception:
        if DEBUG:
            print(traceback.format_exc())
        return None

def parse_ports(data, protocol_number):
    try:
        if protocol_number == 6 and len(data) >= 54:  # TCP
            tcp_header = data[34:54]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            return tcph[0], tcph[1]
        elif protocol_number == 17 and len(data) >= 42:  # UDP
            udp_header = data[34:42]
            udph = struct.unpack('!HHHH', udp_header)
            return udph[0], udph[1]
        else:
            return None, None
    except:
        return None, None

def detect_packet_type(packet, data):
    proto = packet.get("protocol")
    src_port = packet.get("src_port")
    dst_port = packet.get("dst_port")
    proto_num = packet.get("protocol_number")

    if proto == "UDP" and (src_port == 53 or dst_port == 53):
        return "DNS"
    elif proto == "ICMP":
        try:
            icmp_header = data[34:38]
            icmp_type, code, _ = struct.unpack("!BBH", icmp_header)
            if icmp_type == 8:
                return "ICMP Echo Request"
            elif icmp_type == 0:
                return "ICMP Echo Reply"
            else:
                return f"ICMP Type {icmp_type}"
        except:
            return "ICMP"
    elif proto == "TCP" and (src_port == 80 or dst_port == 80):
        return "HTTP"
    elif proto == "TCP" and (src_port == 443 or dst_port == 443):
        return "HTTPS"
    else:
        return proto

def get_tcp_flags(data):
    try:
        if len(data) >= 54:
            tcp_header = data[34:54]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            flags = tcph[5]

            flag_list = []
            if flags & 0x01:
                flag_list.append("FIN")
            if flags & 0x02:
                flag_list.append("SYN")
            if flags & 0x04:
                flag_list.append("RST")
            if flags & 0x08:
                flag_list.append("PSH")
            if flags & 0x10:
                flag_list.append("ACK")
            if flags & 0x20:
                flag_list.append("URG")
            if flags & 0x40:
                flag_list.append("ECE")
            if flags & 0x80:
                flag_list.append("CWR")

            return ",".join(flag_list)
        else:
            return ""
    except:
        return ""

def capture_packets():
    s = None
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.settimeout(1.0)
        if DEBUG:
            print("[*] Sniffer started...")

        while not stop_sniffing.is_set():
            try:
                raw_data, _ = s.recvfrom(65535)
                packet_info = parse_ip_packet(raw_data)
                if packet_info:
                    src_port, dst_port = parse_ports(raw_data, packet_info["protocol_number"])
                    packet_info["src_port"] = src_port
                    packet_info["dst_port"] = dst_port

                    # Type and flags
                    packet_info["packet_type"] = detect_packet_type(packet_info, raw_data)
                    if packet_info["protocol"] == "TCP":
                        packet_info["tcp_flags"] = get_tcp_flags(raw_data)
                    else:
                        packet_info["tcp_flags"] = ""

                    packet_queue.put(packet_info)
            except socket.timeout:
                continue
            except Exception as e:
                if DEBUG:
                    print(f"[ERROR] {e}")
                    print(traceback.format_exc())
                continue

    except Exception as e:
        print(f"[CRITICAL ERROR] Failed to open socket: {e}")
        if DEBUG:
            print(traceback.format_exc())
    finally:
        if s:
            s.close()
            if DEBUG:
                print("[*] Sniffer stopped and socket closed.")

