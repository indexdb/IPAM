# download https://standards-oui.ieee.org/oui/oui.txt
r'''
sudo apt update
sudo apt install -y \
  net-tools \
  samba-common-bin \
  avahi-utils \
  snmp \
  arping \
  iputils-ping \
  iproute2

pip install requests pymysql
'''

import subprocess
import re
import requests
import pymysql
import time
import socket
import struct
import urllib3
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DB_HOST = "localhost"
DB_USER = "phpipam"
DB_PASS = "indexdb@gmail.com"
DB_NAME = "phpipam"
MAX_WORKERS = 10

oui_dict = {}

def ip_to_long(ip_str):
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def ip_from_long(ip_long):
    ip_long = int(ip_long)
    return ".".join(str((ip_long >> (8 * i)) & 0xFF) for i in reversed(range(4)))

def load_oui(filename='oui.txt'):
    global oui_dict
    try:
        with open(filename, 'r') as f:
            for line in f:
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    prefix = parts[0].lower().replace('-', ':')
                    vendor = parts[1].strip()
                    oui_dict[prefix] = vendor
    except FileNotFoundError:
        print("⚠️ OUI file not found.")

def try_getent(ip):
    try:
        result = subprocess.check_output(['getent', 'hosts', ip], text=True).strip()
        return result.split()[1] if result else None
    except:
        return None

def try_nmblookup(ip):
    try:
        result = subprocess.check_output(['nmblookup', '-A', ip], text=True)
        for line in result.splitlines():
            if '<00>' in line and '<GROUP>' not in line:
                return line.strip().split()[0]
    except:
        return None

def try_avahi(ip):
    try:
        result = subprocess.check_output(['avahi-resolve', '-a', ip], text=True).strip()
        return result.split()[1] if result else None
    except:
        return None

def try_snmp(ip, community='public'):
    try:
        result = subprocess.check_output(['snmpget', '-v1', '-c', community, ip, 'iso.3.6.1.2.1.1.5.0'], text=True)
        match = re.search(r'STRING:\s+"?([^"]+)"?', result)
        return match.group(1) if match else None
    except:
        return None

def try_http_title(ip):
    def fetch_and_parse(url):
        try:
            resp = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            if resp.status_code == 403:
                return ''
            html = resp.text
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            return match.group(1).strip() if match else ''
        except:
            return None

    for port in [80, 8080, 32400]:
        url = f"http://{ip}:{port}"
        result = fetch_and_parse(url)
        if result is not None:
            return result
    for scheme in ['https', 'http']:
        url = f"{scheme}://{ip}"
        result = fetch_and_parse(url)
        if result is not None:
            return result
    return None

def resolve_hostname(ip):
    for method in [try_getent, try_nmblookup, try_avahi, try_snmp, try_http_title]:
        name = method(ip)
        if name:
            return name
    return ''

def get_mac(ip):
    try:
        result = subprocess.check_output(['arping', '-c', '2', ip], text=True, stderr=subprocess.DEVNULL)
        match = re.search(r'from\s+([0-9a-f:]{17})', result)
        if match:
            return match.group(1).lower()
    except:
        pass
    try:
        subprocess.call(['ping', '-c', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = subprocess.check_output(['ip', 'neigh', 'show', ip], text=True)
        match = re.search(r'([0-9a-f:]{17})', result)
        if match:
            return match.group(1).lower()
    except:
        pass
    return ''

def clean_vendor(v):
    return re.sub(r'^\(hex\)\s*', '', v, flags=re.IGNORECASE).strip() if v else ''

def get_vendor_local(mac):
    if not mac or len(mac) < 8:
        return 'Unknown'
    prefix = ':'.join(mac.split(':')[:3]).lower()
    return clean_vendor(oui_dict.get(prefix, 'Unknown'))

def get_vendor_online(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        return r.text.strip() if r.status_code == 200 else 'Unknown'
    except:
        return 'Unknown'

def scan_ports(ip, ports=[22,80,443,8080,3306,3389], timeout=1):
    open_ports = []
    for port in ports:
        try:
            with socket.socket() as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(str(port))
        except:
            pass
    return ",".join(open_ports)

def process_ip(record):
    ip_id, ip_long = record
    ip = ip_from_long(ip_long)
    print(f"🔍 Resolving {ip}...")

    hostname = resolve_hostname(ip)
    mac = get_mac(ip)
    vendor = get_vendor_local(mac)
    ports = scan_ports(ip)

    print(f"  ✅ Hostname: '{hostname}'")
    print(f"  ✅ MAC: '{mac}'")
    print(f"  ✅ Vendor (local): '{vendor}'")
    print(f"  ✅ Open ports: '{ports}'")

    return (ip_id, hostname, mac, vendor, ports)

def test_single_ip(ip_str, update=False):
    ip_long = ip_to_long(ip_str)
    record = (0, ip_long)
    _, hostname, mac, vendor, ports = process_ip(record)

    if vendor == 'Unknown' and mac:
        time.sleep(0.5)
        online_vendor = get_vendor_online(mac)
        if online_vendor != 'Unknown':
            vendor = online_vendor
        else:
            vendor = ""

    print(f"IP: {ip_str}")
    print(f"  Hostname: {hostname}")
    print(f"  MAC: {mac}")
    print(f"  Vendor: {vendor}")
    print(f"  Ports: {ports}")

    if update:
        conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
        cursor = conn.cursor()
        sql = "UPDATE ipaddresses SET hostname=%s, mac=%s, description=%s, port=%s WHERE ip_addr=%s"
        cursor.execute(sql, (hostname, mac, vendor, ports, ip_long))
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Updated database.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--force', action='store_true', help='Force update all records')
    parser.add_argument('-s', '--single', metavar='IP', help='Test a single IP (e.g. -s 192.168.1.16)')
    parser.add_argument('--update', action='store_true', help='Update database when using -s')
    args = parser.parse_args()

    load_oui('oui.txt')

    if args.single:
        test_single_ip(args.single, update=args.update)
        return

    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = conn.cursor()

    sql = """
        SELECT id, ip_addr FROM ipaddresses
        WHERE %s OR hostname IS NULL OR hostname = '' OR description IS NULL OR description = ''
    """ % ('TRUE' if args.force else 'FALSE')
    cursor.execute(sql)
    records = cursor.fetchall()

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_ip, record) for record in records]
        for f in as_completed(futures):
            results.append(f.result())

    updated = []
    for ip_id, hostname, mac, vendor, ports in results:
        if vendor == 'Unknown' and mac:
            time.sleep(0.5)
            online_vendor = get_vendor_online(mac)
            if online_vendor != 'Unknown':
                vendor = online_vendor
            else:
                vendor = ""
        elif not mac:
            vendor = ""
        updated.append((ip_id, hostname, mac, vendor, ports))

    for ip_id, hostname, mac, vendor, ports in updated:
        sql = "UPDATE ipaddresses SET hostname=%s, mac=%s, description=%s, port=%s WHERE id=%s"
        cursor.execute(sql, (hostname, mac, vendor, ports, ip_id))

    conn.commit()
    cursor.close()
    conn.close()

if __name__ == "__main__":
    main()
