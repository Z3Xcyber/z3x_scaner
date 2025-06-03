import socket
import ssl
import datetime
import dns.resolver                                             import whois
import requests
import os
from datetime import datetime

SECURITYTRAILS_API_KEY = "YOUR_API_KEY_HERE"  # <-- ضع مفتاحك هنا
common_subdomains = ["mail", "ftp", "cpanel", "webmail", "direct", "ns1", "ns2", "dev", "test", "server"]

def get_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8']
    return resolver

def scan_domain(domain):
    output = f"IP.s(\\/)\n\n[+] Domain: {domain}\n\n"
    resolver = get_resolver()

    try:
        output += "[✔️] A Records:\n"
        a_records = resolver.resolve(domain, 'A')
        for r in a_records:
            output += f"  - {r}\n"
    except: output += "  - No A record found.\n"

    output += "\n[🌐] HTTP/HTTPS Status:\n"
    for url in [f"https://{domain}", f"http://{domain}"]:
        try:
            r = requests.get(url, timeout=5)
            output += f"  - {url} : {r.status_code}\n"
        except Exception as e:
            output += f"  - {url} : {e}\n"

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                output += f"\n[🔐] SSL Expires: {exp_date}\n"
    except Exception as e:
        output += f"\n[🔐] SSL Error: {e}\n"

    try:
        output += "\n[📧] MX Records:\n"
        mx = resolver.resolve(domain, 'MX')
        for r in mx:
            output += f"  - {r.exchange} (priority {r.preference})\n"
    except:
        output += "  - No MX record found.\n"

    try:
        output += "\n[🔁] CNAME Record:\n"
        cname = resolver.resolve(domain, 'CNAME')
        for r in cname:
            output += f"  - {r.target}\n"
    except:
        output += "  - No CNAME record found.\n"

    try:
        output += "\n[ℹ️] WHOIS Info:\n"
        info = whois.whois(domain)
        output += f"  - Domain Name: {info.domain_name}\n"
        output += f"  - Registrar: {info.registrar}\n"
        output += f"  - Creation Date: {info.creation_date}\n"
        output += f"  - Expiry Date: {info.expiration_date}\n"
    except Exception as e:
        output += f"  - WHOIS Error: {e}\n"

    output += "\n[🕵️‍♂️] محاولة كشف IP من Subdomains:\n"
    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            sub_a = resolver.resolve(full_domain, 'A')
            for ip in sub_a:
                output += f"  - {full_domain} : {ip}\n"
        except:
            pass

    output += "\n[🔍] تحليل IP من MX/CNAME:\n"
    try:
        mx = resolver.resolve(domain, 'MX')
        for r in mx:
            mx_domain = str(r.exchange).rstrip('.')
            try:
                ip = socket.gethostbyname(mx_domain)
                output += f"  - MX {mx_domain} => {ip}\n"
            except: pass
    except: pass

    try:
        cname = resolver.resolve(domain, 'CNAME')
        for r in cname:
            cname_domain = str(r.target).rstrip('.')
            try:
                ip = socket.gethostbyname(cname_domain)
                output += f"  - CNAME {cname_domain} => {ip}\n"
            except: pass
    except: pass

    output += "\n[↩️] Reverse DNS:\n"
    try:
        for r in a_records:
            try:
                host, _, _ = socket.gethostbyaddr(r.to_text())
                output += f"  - {r} => {host}\n"
            except:
                output += f"  - {r} => No PTR Record\n"
    except:
        pass

    output += "\n[📜] DNS History (A Records):\n"
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
        output += f"  - Error fetching DNS history: {e}\n"

    return output

if __name__ == "__main__":
    domain = input("أدخل الدومين: ").strip()
    if not domain:
        print("يرجى إدخال دومين صالح.")
        exit()

    result = scan_domain(domain)

    print("\n" + result)

    now = datetime.now().strftime("%d-%m-%Y--%H-%M")
    filename = f"report-{domain}-{now}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(result)

    print(f"\n[💾] تم حفظ التقرير في: {filename}")