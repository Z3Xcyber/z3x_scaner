import socket
import ssl
import datetime
import dns.resolver
import whois
import requests
import os
import time
from datetime import datetime
from colorama import init, Fore, Back, Style

# Initialize colorama
init()

# Constants
SECURITYTRAILS_API_KEY = "YOUR_API_KEY_HERE"  # <-- Place your API key here
common_subdomains = ["mail", "ftp", "cpanel", "webmail", "direct", "ns1", "ns2", "dev", "test", "server"]
VERSION = "2.0"
AUTHOR = "Z3X Team"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    print(Fore.RED + r"""
 _____  _____  __  __          ____   ____    _    _   _ _____ ____
|__  / |___ /  \ \/ /         / ___| / ___|  / \  | \ | | ____|  _ \
  / /    |_ \   \  /          \___ \| |     / _ \ |  \| |  _| | |_) |
 / /_   ___) |  /  \           ___) | |___ / ___ \| |\  | |___|  _ <
/____| |____/  /_/\_\  _____  |____/ \____/_/   \_\_| \_|_____|_| \_\
                      |_____|
    """ + Style.RESET_ALL)
    print(Fore.CYAN + f"Z3X DOMAIN SCANNER v{VERSION}".center(80))
    print(Fore.YELLOW + f"by {AUTHOR}".center(80) + Style.RESET_ALL)
    print("\n")

def get_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google and Cloudflare DNS
    return resolver

def scan_domain(domain):
    output = f"Z3X SCAN REPORT\n\n[+] Target Domain: {domain}\n"
    output += f"[+] Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    resolver = get_resolver()

    # A Records
    try:
        output += "[+] A Records:\n"
        a_records = resolver.resolve(domain, 'A')
        for r in a_records:
            output += f"  - {r}\n"
    except Exception as e:
        output += f"  - A record lookup failed: {str(e)}\n"

    # HTTP/HTTPS Status
    output += "\n[+] HTTP/HTTPS Status:\n"
    protocols = {
        'http': 80,
        'https': 443,
        'ftp': 21,
        'ssh': 22
    }
    
    for proto, port in protocols.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((domain, port))
            status = "OPEN" if result == 0 else "CLOSED"
            output += f"  - {proto.upper()} ({port}): {status}\n"
            sock.close()
        except Exception as e:
            output += f"  - {proto.upper()} check failed: {str(e)}\n"

    # SSL Certificate
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_date - datetime.now()).days
                output += f"\n[+] SSL Certificate:\n"
                output += f"  - Issuer: {issuer.get('organizationName', 'Unknown')}\n"
                output += f"  - Expires: {exp_date} ({days_left} days remaining)\n"
                output += f"  - Version: {cert.get('version', 'Unknown')}\n"
    except Exception as e:
        output += f"\n[+] SSL Certificate Error: {str(e)}\n"

    # MX Records
    try:
        output += "\n[+] MX Records:\n"
        mx = resolver.resolve(domain, 'MX')
        for r in mx:
            output += f"  - {r.exchange} (priority {r.preference})\n"
    except Exception as e:
        output += f"  - MX record lookup failed: {str(e)}\n"

    # CNAME Record
    try:
        output += "\n[+] CNAME Record:\n"
        cname = resolver.resolve(domain, 'CNAME')
        for r in cname:
            output += f"  - {r.target}\n"
    except Exception as e:
        output += f"  - CNAME record lookup failed: {str(e)}\n"

    # WHOIS Info
    try:
        output += "\n[+] WHOIS Information:\n"
        info = whois.whois(domain)
        output += f"  - Domain Name: {info.domain_name}\n"
        output += f"  - Registrar: {info.registrar}\n"
        output += f"  - Creation Date: {info.creation_date}\n"
        output += f"  - Expiry Date: {info.expiration_date}\n"
        output += f"  - Name Servers: {info.name_servers}\n"
    except Exception as e:
        output += f"  - WHOIS lookup failed: {str(e)}\n"

    # Subdomain Enumeration
    output += "\n[+] Subdomain Enumeration:\n"
    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            sub_a = resolver.resolve(full_domain, 'A')
            for ip in sub_a:
                output += f"  - {full_domain} => {ip}\n"
        except:
            pass

    # IP Analysis from MX/CNAME
    output += "\n[+] IP Analysis from MX/CNAME:\n"
    try:
        mx = resolver.resolve(domain, 'MX')
        for r in mx:
            mx_domain = str(r.exchange).rstrip('.')
            try:
                ip = socket.gethostbyname(mx_domain)
                output += f"  - MX {mx_domain} => {ip}\n"
            except:
                pass
    except:
        pass

    try:
        cname = resolver.resolve(domain, 'CNAME')
        for r in cname:
            cname_domain = str(r.target).rstrip('.')
            try:
                ip = socket.gethostbyname(cname_domain)
                output += f"  - CNAME {cname_domain} => {ip}\n"
            except:
                pass
    except:
        pass

    # Reverse DNS
    output += "\n[+] Reverse DNS Lookup:\n"
    try:
        for r in a_records:
            try:
                host, _, _ = socket.gethostbyaddr(r.to_text())
                output += f"  - {r} => {host}\n"
            except:
                output += f"  - {r} => No PTR Record\n"
    except:
        pass

    # DNS History (A Records)
    if SECURITYTRAILS_API_KEY != "YOUR_API_KEY_HERE":
        output += "\n[+] DNS History (A Records):\n"
        try:
            headers = {"apikey": SECURITYTRAILS_API_KEY}
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            response = requests.get(url, headers=headers)
            data = response.json()

            if "records" in data:
                for record in data["records"]:
                    ip = record.get("values", [])[0] if record.get("values") else "Unknown"
                    date = record.get("first_seen", "N/A")
                    output += f"  - {ip} (first seen: {date})\n"
            else:
                output += "  - No historical A records found.\n"
        except Exception as e:
            output += f"  - Error fetching DNS history: {str(e)}\n"
    else:
        output += "\n[!] DNS History feature disabled (API key not configured)\n"

    return output

def main():
    clear_screen()
    show_banner()
    
    while True:
        try:
            domain = input(Fore.GREEN + "[?] Enter domain to scan (or 'exit' to quit): " + Style.RESET_ALL).strip()
            
            if domain.lower() == 'exit':
                print(Fore.YELLOW + "\n[+] Goodbye!" + Style.RESET_ALL)
                break
                
            if not domain:
                print(Fore.RED + "[!] Please enter a valid domain." + Style.RESET_ALL)
                continue
                
            print(Fore.CYAN + f"\n[+] Scanning {domain}..." + Style.RESET_ALL)
            
            # Add some fake progress for dramatic effect
            for i in range(1, 6):
                print(Fore.YELLOW + f"[{i}/5] Scanning in progress..." + Style.RESET_ALL, end='\r')
                time.sleep(0.3)
                
            result = scan_domain(domain)
            
            clear_screen()
            show_banner()
            print(Fore.GREEN + "\nSCAN RESULTS:\n" + Style.RESET_ALL)
            print(result)
            
            now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"z3x_scan_{domain}_{now}.txt"
            
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(result)
                print(Fore.GREEN + f"\n[+] Report saved to: {filename}" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"\n[!] Error saving report: {str(e)}" + Style.RESET_ALL)
                
            input(Fore.YELLOW + "\nPress Enter to scan another domain..." + Style.RESET_ALL)
            clear_screen()
            show_banner()
            
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Scan interrupted by user." + Style.RESET_ALL)
            break
        except Exception as e:
            print(Fore.RED + f"\n[!] An error occurred: {str(e)}" + Style.RESET_ALL)
            input(Fore.YELLOW + "\nPress Enter to continue..." + Style.RESET_ALL)
            clear_screen()
            show_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Program terminated by user." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\n[!] Fatal error: {str(e)}" + Style.RESET_ALL)
