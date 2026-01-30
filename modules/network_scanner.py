import ipaddress
import subprocess
from .arp_utils import aggressive_arp_ping

def find_local_network_devices(local_ip, mask):
    """Поиск устройств в локальной сети разными методами"""
    devices = []
    found_ips = set()
    
    # Определяем сеть
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{mask}", strict=False)
        network_prefix = str(network.network_address).rsplit('.', 1)[0]
        # Добавляем себя в список устройств
        devices.append({'ip': local_ip, 'mac': 'наш компьютер'})
        found_ips.add(local_ip)
    except:
        ip_parts = local_ip.split('.')
        network_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
        # Добавляем себя в список устройств
        devices.append({'ip': local_ip, 'mac': 'наш компьютер'})
        found_ips.add(local_ip)
    
    print(f"\n\033[1;36m🔍 Агрессивное сканирование сети {network_prefix}.0/{mask}\033[0m")
    print("\033[1;33mℹ  Использую комбинированные методы сканирования...\033[0m")
    
    # Метод 1: Быстрое сканирование ARP
    print(f"\033[1;33m Сканирование ARP...\033[0m")
    # Сканируем только часть сети для скорости
    for last_octet in range(1, 255):
        if last_octet % 50 == 0:
            print(f"  \033[1;33m[*] Проверено {last_octet} адресов...\033[0m")
        
        target_ip = f"{network_prefix}.{last_octet}"
        if target_ip in found_ips:
            continue
            
        result = aggressive_arp_ping(target_ip, timeout=0.1, retry=1)
        if result:
            devices.append(result)
            found_ips.add(result['ip'])
    
    print(f"\033[1;33m Сканирование с помощью nmap (если доступен)...\033[0m")
    
    # Метод 2: Используем nmap если есть (самый надежный метод)
    try:
        # Проверяем, установлен ли nmap
        subprocess.run(["which", "nmap"], capture_output=True, check=True)
        
        print("  \033[1;33m[*] Запускаю nmap...\033[0m")
        
        # Быстрое сканирование с nmap
        result = subprocess.run(
            f"nmap -sn -n --min-parallelism 10 --max-rtt-timeout 7000ms {network_prefix}.0/24",
            shell=True, capture_output=True, text=True, timeout=7000
        )
        
        if result.returncode == 0:
            # Парсим вывод nmap
            lines = result.stdout.split('\n')
            current_ip = None
            
            for line in lines:
                if 'Nmap scan report for' in line:
                    parts = line.split()
                    current_ip = parts[4]
                elif 'MAC Address:' in line and current_ip:
                    parts = line.split()
                    mac = parts[2]
                    
                    if current_ip not in found_ips and current_ip != local_ip:
                        devices.append({'ip': current_ip, 'mac': mac})
                        found_ips.add(current_ip)
                        current_ip = None
    except:
        print("  \033[1;33m[!] nmap не найден или произошла ошибка\033[0m")
    
    # Сортируем устройства по IP
    devices.sort(key=lambda x: [int(octet) for octet in x['ip'].split('.')] if x['ip'] != local_ip else [0,0,0,0])
    
    return devices
