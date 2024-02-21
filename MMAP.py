import socket
import signal
from scapy.all import ARP, Ether, srp

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)
    try:
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except socket.error:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def scan(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    result = srp(arp_request, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_ports(ip, ports, open_timeout=1):
    open_ports = []
    closed_ports = []
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(open_timeout)
        
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            else:
                closed_ports.append(port)
        except KeyboardInterrupt:
            print("\nPrzerwano skanowanie portów.")
            break
        finally:
            sock.close()

    print("Zeskanowane otwarte porty:")
    for port in open_ports:
        print(f"{port}: {get_service_name(port)}")

    print("Zeskanowane zamknięte porty:")
    for port in closed_ports:
        print(f"{port}: {get_service_name(port)}")

    return open_ports

def get_service_name(port):
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3389: "RDP"
    }
    return services.get(port, "Nierozpoznane")

def select_device(devices):
    print("\nDostępne urządzenia:")
    for idx, device in enumerate(devices):
        print(f"{idx + 1}. {device['ip']} ({device['mac']})")

    while True:
        try:
            choice = int(input("\nWybierz numer urządzenia do skanowania portów (1-{0}): ".format(len(devices))))
            if 1 <= choice <= len(devices):
                return devices[choice - 1]
            else:
                print("Nieprawidłowy numer. Spróbuj ponownie.")
        except ValueError:
            print("Nieprawidłowy numer. Spróbuj ponownie.")

def get_mac_vendor(mac_address, oui_file_path):
    mac_prefix = mac_address[:8].replace(':', '').upper()
    try:
        with open(oui_file_path, 'r') as f:
            for line in f:
                columns = line.strip().split(maxsplit=2)
                if len(columns) >= 2 and columns[1] == mac_prefix:
                    return columns[2]
    except FileNotFoundError:
        print("Błąd: Brak pliku oui.txt")
    return "Nieznany"

def signal_handler(sig, frame):
    print("\nPrzerwano skrypt.")
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    local_ip = get_local_ip()
    print(f"Adres IP Twojego urządzenia: {local_ip}")

    target_ip = f"{local_ip.split('.')[0]}.{local_ip.split('.')[1]}.{local_ip.split('.')[2]}.0/24"
    devices = scan(target_ip)

    selected_device = select_device(devices)
    print(f"\nWybrano urządzenie: {selected_device['ip']} ({selected_device['mac']})")
    oui_file_path = "oui.txt"  # Ścieżka do pliku oui.txt
    print(f"Producent: {get_mac_vendor(selected_device['mac'], oui_file_path)}")

    try:
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]
        open_ports = scan_ports(selected_device['ip'], ports_to_scan)
        selected_device['open_ports'] = open_ports
    except Exception as e:
        print(f"Błąd podczas skanowania portów: {e}")


