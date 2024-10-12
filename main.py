import socket
import threading
import logging
import datetime

from templates.protocols import ethernet_frame, ipv4_packet, icmp_packet, udp_packet, tcp_packet
from templates.helper import get_interfaces, PROTOCOLS
from templates.validator import validate_with_route_table

# Настройка логирования
logging.basicConfig(level=logging.INFO, filename="firewall.log", filemode="w")

# Создание сокета для отправки пакетов
send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

def send_packet(conn: socket.socket, payload, dst_ip):
    """Отправка пакета на указанный IP адрес."""
    try:
        conn.sendto(payload, (dst_ip, 0))
    except PermissionError as e:
        print(f"Permission Error: {e}")
    except OSError as e:
        print(f"OS Error: {e}")

def bind_sockets(interface):
    """Создание сокета для прослушивания пакетов на указанном интерфейсе."""
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    conn.bind((interface[0], 0))
    
    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)
            dest_mac, src_mac, eth_protocol, eth_data = ethernet_frame(raw_data)  # Получение деталей кадра
            
            if eth_protocol == 8:  # Проверка на IPv4
                s_addr, d_addr, protocol, ip_header = ipv4_packet(eth_data[14:34])
                logging.info(f"[{datetime.datetime.now()}] {interface[0]} ({d_addr}) > {PROTOCOLS[protocol]}")
                
                src_port, dst_port = 0, 0
                if protocol == 6:  # TCP
                    src_port, dst_port = tcp_packet(eth_data[34:54])
                elif protocol == 17:  # UDP
                    src_port, dst_port, size, data = udp_packet(eth_data[34:42])
                
                # По умолчанию весь трафик запрещен.
                # Любые маршруты в файле правил будут разрешены.
                if validate_with_route_table(s_addr, d_addr, src_port, dst_port):
                    send_packet(send_sock, eth_data[14:], d_addr)
                else:
                    logging.error(f"<FAILED ROUTE>[{datetime.datetime.now()}] {interface[0]} ({s_addr}, {d_addr}) > {PROTOCOLS[protocol]}")
                    
    except KeyboardInterrupt:
        print("n[END] STOPPED")

if __name__ == "__main__":
    interfaces = get_interfaces()

    if len(interfaces.items()) < 4:
        print("Not enough interfaces")
        exit()

    for key in interfaces.keys():
        tr = threading.Thread(target=bind_sockets, args=([key, interfaces[key]],), name=key)
        tr.setDaemon(True)
        tr.start()

    print("FIREWALL IS RUNNING")
