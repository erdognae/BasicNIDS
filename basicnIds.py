import socket
import struct
import os

# Dosya kontrolü ve okunması
if not os.path.exists('scrapy_iplist.txt'): # Zararlı ip adreslerinin bulunduğu dosya. Bu dosya dinamik olarak web scraping  ile sürekli güncellenecek şekilde ayarlanabilir.    
    exit()

with open('scrapy_iplist.txt', 'r') as file:
    monitored_ips = [line.strip() for line in file.readlines()]

try:
    host = socket.gethostbyname(socket.gethostname()) #Bu kod, bilgisayarın ağ paketlerini doğrudan dinlemeye ve manipüle etmeye yarayan bir ham soket oluştururr. 
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)  # IPPROTO_TCP daha yaygın
    s.bind((host, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Header dahil etmek için set işlemi yapılır.
    print(f"Socket successfully created on host {host}. Monitoring IPs: {monitored_ips}")
except PermissionError:
    print("PermissionError: Root or administrator privileges are required to use raw sockets.")
    exit()
except Exception as e:
    print(f"An error occurred: {e}")
    exit()

while True:
    packet, addr = s.recvfrom(65565) #gelen paket uzunluğu
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)  # "4s" kısımları sırasııyla ip adreslerini temsil eder. B: 1byte H:2byte'lık IPv4 paketindeki kısımları temsil eder. !: Big Endian
     
    version_ihl = iph[0]  # version bilgisi alınır ve aşağıdaki iki satır ile birlikte ipv4 paket uzunluğu hesaplanır.
    ihl = version_ihl & 0xF
    iph_length = ihl * 4  

    src_addr = socket.inet_ntoa(iph[8])  # socket.inet_ntoa() fonksiyonu, binary (ikili) formatta bir IP adresini, insan tarafından okunabilir bir IPv4 adresi formatına dönüştüren bir Python fonksiyonudur. 4s listedeki 8 ve 9. elemanlara yani ip adreslerine denk gelir.
    dst_addr = socket.inet_ntoa(iph[9])

    if src_addr in monitored_ips: # Zararlı trafikler yakalanmış oldu burda.
        print(f"Alert: Incoming connection for blacklisted IP {src_addr}!") 

    if dst_addr in monitored_ips:
        print(f"Alert: Outgoing connection for blacklisted IP {dst_addr}!")


# iph örneğin (69, 0, 20, 54321, 0, 0, 64, 6, b'\x7f\x00\x00\x01', b'\x7f\x00\x00\x01') şeklinde bir tupledir.
