import os
import sys
import time
import socket
import struct
import select
from scapy.all import IP, ICMP, send, sr1

def main():
    while True:
        try:
            input_command = input("Введите команду: ").strip()
            if not input_command:
                continue

            parts = input_command.split()
            if len(parts) != 2 or parts[0].lower() != "tracert":
                print("Ошибка: используйте команду в формате tracert <IP>\n")
                continue

            target_host = parts[1]
            traceroute(target_host)
            print("\nТрассировка завершена.\n")

        except KeyboardInterrupt:
            print("\nПрограмма завершена.")
            break

def traceroute(target_host):
    try:
        target_address = socket.gethostbyname(target_host)
        resolved_hostname = socket.getfqdn(target_address)
        print(f"\nТрассировка маршрута к {resolved_hostname} [{target_address}]")
        print("с максимальным числом прыжков 30:\n")

        for ttl in range(1, 31):
            hop_address = None
            times = []

            for _ in range(3):
                start_time = time.time()
                reply = sr1(IP(dst=target_address, ttl=ttl)/ICMP(), timeout=3, verbose=0)
                elapsed_time = (time.time() - start_time) * 1000  # В миллисекундах

                if reply:
                    hop_address = reply.src
                    times.append(elapsed_time)
                else:
                    times.append(-1)

            print_traceroute_line(ttl, times, hop_address)

            if hop_address == target_address:
                break

    except socket.gaierror as e:
        print(f"Ошибка при разрешении хоста: {e}")
    except Exception as e:
        print(f"Произошла ошибка: {e}")

def print_traceroute_line(ttl, times, hop_address):
    time1 = f"{times[0]:.0f} ms" if times[0] != -1 else "*"
    time2 = f"{times[1]:.0f} ms" if times[1] != -1 else "*"
    time3 = f"{times[2]:.0f} ms" if times[2] != -1 else "*"

    if hop_address is None:
        print(f"{ttl:3}   {time1:>7}   {time2:>7}   {time3:>7}   Превышен интервал ожидания для запроса.")
    else:
        try:
            hostname = socket.gethostbyaddr(hop_address)[0]
            if hostname == hop_address:
                print(f"{ttl:3}   {time1:>7}   {time2:>7}   {time3:>7}   {hop_address}")
            else:
                print(f"{ttl:3}   {time1:>7}   {time2:>7}   {time3:>7}   {hostname} [{hop_address}]")
        except socket.herror:
            print(f"{ttl:3}   {time1:>7}   {time2:>7}   {time3:>7}   {hop_address}")

if __name__ == "__main__":
    main()
