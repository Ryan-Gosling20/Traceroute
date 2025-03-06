import socket
import os
import struct
import time
import select
import sys
from colorama import init, Fore, Style

# Инициализация colorama для Windows
init(autoreset=True)

ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp')

def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_packet(seq_number):
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, os.getpid() & 0xFFFF, seq_number)
    data = struct.pack("d", time.time())
    my_checksum = checksum(header + data)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), os.getpid() & 0xFFFF, seq_number)
    return header + data

def send_ping(sock, addr, seq_number, ttl):
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    packet = create_packet(seq_number)
    sock.sendto(packet, (addr, 1))

def receive_ping(sock, timeout):
    time_left = timeout
    while time_left > 0:
        start_time = time.time()
        ready = select.select([sock], [], [], time_left)
        how_long_in_select = (time.time() - start_time)
        if ready[0] == []:
            return None, None

        time_received = time.time()
        rec_packet, addr = sock.recvfrom(1024)

        icmp_header = rec_packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack("bbHHh", icmp_header)

        if type == 11:
            return time_received - start_time, addr[0]
        elif type == 0:
            return time_received - start_time, addr[0]

        time_left = time_left - how_long_in_select
    return None, None

def traceroute(dest_addr, max_hops=30, timeout=2, pings_per_hop=3, resolve_hostnames=False):
    try:
        dest_ip = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        print(f"{Fore.RED}Не удается разрешить адрес {dest_addr}{Style.RESET_ALL}")
        sys.exit()

    print(f"{Fore.CYAN}\nТрассировка до {dest_addr} ({dest_ip}) с максимальным количеством хопсов {max_hops}:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'TTL':<5}{'IP-адрес':<20}{'Время отклика'}{Style.RESET_ALL}")
    print("-" * 40)

    for ttl in range(1, max_hops + 1):
        print(f"{Fore.MAGENTA}{ttl:<5}{Style.RESET_ALL}", end="")

        responses = []
        for attempt in range(pings_per_hop):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
                sock.settimeout(timeout)
                send_ping(sock, dest_ip, ttl, ttl)
                time_spent, current_addr = receive_ping(sock, timeout)
                sock.close()

                if time_spent is None:
                    responses.append(f"{Fore.RED}*{Style.RESET_ALL}")
                else:
                    if resolve_hostnames:
                        try:
                            current_host = socket.gethostbyaddr(current_addr)[0]
                        except socket.herror:
                            current_host = current_addr
                        responses.append(f"{Fore.GREEN}{current_host} ({current_addr}) {time_spent*1000:.2f} ms{Style.RESET_ALL}")
                    else:
                        responses.append(f"{Fore.GREEN}{current_addr} {time_spent*1000:.2f} ms{Style.RESET_ALL}")

                    if current_addr == dest_ip:
                        print("  ".join(responses))
                        print(f"{Fore.CYAN}\nТрассировка завершена.{Style.RESET_ALL}")
                        return

            except socket.error as e:
                print(f"{Fore.RED}\nОшибка при отправке пакета: {e}{Style.RESET_ALL}")
                sys.exit()

        print("  ".join(responses))
    print(f"{Fore.CYAN}\nТрассировка завершена.{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Fore.RED}Использование: python traceroute.py <адрес> [--resolve]{Style.RESET_ALL}")
        sys.exit(1)

    target = sys.argv[1]
    resolve = "--resolve" in sys.argv

    traceroute(target, resolve_hostnames=resolve)
