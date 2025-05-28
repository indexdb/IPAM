# download https://standards-oui.ieee.org/oui/oui.txt
r'''
sudo apt update
sudo apt install -y \
  net-tools \             # for getent and ifconfig (getent hosts)
  samba-common-bin \      # for nmblookup
  avahi-utils \           # for avahi-resolve
  snmp \                  # for snmpget
  arping \                # for arping
  iputils-ping \          # for ping
  iproute2 \              # for `ip neigh show`

pip install requests pymysql
'''

import subprocess
import re
import requests
import pymysql
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import struct
import urllib3

# Disable warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DB_HOST = "localhost"
DB_USER = "phpipam"
DB_PASS = "indexdb@gmail.com"
DB_NAME = "phpipam"

MAX_WORKERS = 10  # Number of threads for concurrent processing

oui_dict = {}  # Local OUI dictionary for vendor lookup

def ip_to_long(ip_str):
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def load_oui(filename='oui.txt'):
    """
    Load OUI prefixes from a file into a dictionary.
    Expected format: first 3 bytes of MAC (e.g. '00:23:24') map to vendor string.
    """
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
        print("OUI file not found, local vendor lookup will be limited.")


def ip_from_long(ip_long):
    """
    Convert long integer IP to dotted quad string.
    """
    ip_long = int(ip_long)
    return ".".join(str((ip_long >> (8 * i)) & 0xFF) for i in reversed(range(4)))


def try_getent(ip):
    """
    Try resolving hostname using getent hosts.
    """
    try:
        result = subprocess.check_output(['getent', 'hosts', ip], text=True).strip()
        if result:
            return result.split()[1]
    except subprocess.CalledProcessError:
        return None


def try_nmblookup(ip):
    """
    Try resolving hostname using nmblookup.
    """
    try:
        result = subprocess.check_output(['nmblookup', '-A', ip], text=True)
        lines = result.splitlines()
        for line in lines:
            if '<00>' in line and '<GROUP>' not in line:
                return line.strip().split()[0]
    except subprocess.CalledProcessError:
        return None


def try_avahi(ip):
    """
    Try resolving hostname using avahi-resolve.
    """
    try:
        result = subprocess.check_output(['avahi-resolve', '-a', ip], text=True).strip()
        parts = result.split()
        if len(parts) >= 2:
            return parts[1]
    except subprocess.CalledProcessError:
        return None


def try_snmp(ip, community='public'):
    """
    Try resolving hostname using SNMP query for sysName.
    """
    try:
        oid = 'iso.3.6.1.2.1.1.5.0'  # sysName.0 OID
        result = subprocess.check_output(['snmpget', '-v1', '-c', community, ip, oid], text=True)
        match = re.search(r'STRING:\s+"?([^"]+)"?', result)
        if match:
            return match.group(1)
    except subprocess.CalledProcessError:
        return None

def try_http_title(ip):
    """
    Attempts to retrieve the title of a web server at the given IP address.
    Supports:
        1. <title> tag
        2. <meta http-equiv="refresh"> redirect + <title>
        3. <script>window.top.location.href=... JavaScript redirect
        4. <meta name="description"> content
        5. <meta property="og:title"> (Open Graph title)
    For ports 80, 8080, 1025, 2500, 8384, 32400: only tries http scheme.
    For others: tries https first, then http.
    Returns:
        - String with title/description/og:title
        - Empty string if HTTP 403 or title is 'forbidden'
        - None on connection failure or error
    """
    special_http_ports = [8080, 2500, 8384, 16992, 32400]
    special_https_ports = [1025]
    def fetch_and_parse(url):
        try:
            session = requests.Session()
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = session.get(url, headers=headers, verify=False, timeout=3, allow_redirects=True)

            if resp.status_code == 403:
                return ''

            resp.encoding = resp.apparent_encoding
            html = resp.text
            
            # Handle <meta http-equiv="refresh" ...>
            meta_match = re.search(
                r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?\s*\d+\s*;\s*(?:url|URL)\s*=\s*[\'"]?([^\'">]+)',
                html, re.IGNORECASE
            )
            if meta_match:
                redirect_url = requests.compat.urljoin(resp.url, meta_match.group(1).strip())
                resp = session.get(redirect_url, headers=headers, verify=False, timeout=3)
                resp.encoding = resp.apparent_encoding
                html = resp.text

            # Handle JavaScript redirect: <script>window.top.location.href = '...' </script>
            js_redirect = re.search(
                r'window\.top\.location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
                html, re.IGNORECASE
            )
            if js_redirect:
                redirect_url = requests.compat.urljoin(resp.url, js_redirect.group(1).strip())
                resp = session.get(redirect_url, headers=headers, verify=False, timeout=3)
                resp.encoding = resp.apparent_encoding
                html = resp.text

            # Try <title>
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                if title.lower() == 'forbidden':
                    return ''
                return title

            # Try <meta name="description">
            meta_desc = re.search(
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
                html, re.IGNORECASE
            )
            if meta_desc:
                return meta_desc.group(1).strip()

            # Try <meta property="og:title">
            og_title = re.search(
                r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
                html, re.IGNORECASE
            )
            if og_title:
                return og_title.group(1).strip()

            return ''

        except Exception as e:
            # You can uncomment next two lines to debug
            # import traceback
            # traceback.print_exc()
            return None
    
    # For this example, let's just test the special_http_ports
    for port in special_http_ports:        
        url = f'http://{ip}:{port}'

        result = fetch_and_parse(url)
        if result is not None:
            return result
    for port in special_https_ports:        
        url = f'https://{ip}:{port}'
        result = fetch_and_parse(url)
        if result is not None:
            return result

    # If none matched, try default without port (usually 80/443)
    for scheme in ['https', 'http']:
        url = f'{scheme}://{ip}'
        result = fetch_and_parse(url)
        if result is not None:
            return result

    return None


def resolve_hostname(ip):
    """
    Attempt hostname resolution using various methods in order.
    Return hostname string or empty string if none found.
    """
    methods = [
        try_getent,
        try_nmblookup,
        try_avahi,
        try_snmp,
        try_http_title,
    ]
    for method in methods:
        hostname = method(ip)
        if hostname:
            return hostname
    return ''


def get_mac(ip):
    """
    Try to get MAC address of the IP using arping or ping+ip neigh.
    Returns MAC string in lowercase or empty string if not found.
    """
    try:
        result = subprocess.check_output(['arping', '-c', '2', ip], text=True, stderr=subprocess.DEVNULL)
        match = re.search(r'from\s+([0-9a-f:]{17})', result)
        if match:
            return match.group(1).lower()
    except Exception:
        pass
    try:
        subprocess.call(['ping', '-c', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = subprocess.check_output(['ip', 'neigh', 'show', ip], text=True)
        match = re.search(r'([0-9a-f:]{17})', result)
        if match:
            return match.group(1).lower()
    except Exception:
        pass
    return ''


def clean_vendor(vendor_str):
    """
    Remove unwanted prefixes like '(hex)' from vendor string.
    """
    if not vendor_str:
        return ''
    # Remove leading '(hex)' or '(HEX)' with optional trailing spaces
    return re.sub(r'^\(hex\)\s*', '', vendor_str, flags=re.IGNORECASE).strip()


def get_vendor_local(mac):
    """
    Lookup vendor from local OUI dictionary by first 3 bytes of MAC.
    Remove unwanted prefixes like '(hex)'.
    Return 'Unknown' if not found or MAC is empty/invalid.
    """
    if not mac or len(mac) < 8:
        return 'Unknown'
    prefix = ':'.join(mac.split(':')[:3])
    raw_vendor = oui_dict.get(prefix.lower(), 'Unknown')
    return clean_vendor(raw_vendor)  # Only local vendor cleaned


def get_vendor_online(mac):
    """
    Query online API for vendor info by MAC.
    Return vendor string as-is or 'Unknown' if failed.
    """
    if not mac:
        return ''
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text.strip()  # Do NOT clean here
    except Exception:
        pass
    return 'Unknown'


def scan_ports(ip, ports=[20,21,22,23,25,53,80,110,143,443,445,1025,2500,3306,3389,5900,8080,8384,16992,32400], timeout=1):
    """
    Scan given ports on the IP, return comma-separated string of open ports.
    """
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(str(port))
        except Exception:
            pass
    return ",".join(open_ports)


def process_ip(record):
    """
    Resolve hostname, MAC, local vendor, and scan ports for a given IP record.
    Returns tuple (ip_id, hostname, mac, vendor, ports).
    """
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


def main():
    load_oui('oui.txt')  # Load local OUI data

    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT id, ip_addr
    FROM ipaddresses
    WHERE (hostname IS NULL OR hostname = '')
    OR (description IS NULL OR description = '')
    """)

    records = cursor.fetchall()

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_ip, record) for record in records]

        for future in as_completed(futures):
            results.append(future.result())

    # Query online vendor info sequentially with delay to avoid rate limiting
    updated_results = []
    
    for ip_id, hostname, mac, vendor, ports in results:
        if vendor == 'Unknown' and mac:
            time.sleep(0.5)  # 500ms delay between API calls
            online_vendor = get_vendor_online(mac)
            if online_vendor:
                vendor = online_vendor
        updated_results.append((ip_id, hostname, mac, vendor, ports))

    # Update database with final resolved data including port info
    for ip_id, hostname, mac, vendor, ports in updated_results:
        sql = "UPDATE ipaddresses SET hostname = %s, mac = %s, description = %s, port = %s WHERE id = %s"        
        cursor.execute(sql, (hostname, mac, vendor, ports, ip_id))

    conn.commit()
    cursor.close()
    conn.close()

def test_single_ip(ip_str):

    ip_long = ip_to_long(ip_str)
    record = (0, ip_long)  # 
    
    print(f"IP: {ip_str}")
    ip_id, hostname, mac, vendor, ports = process_ip(record)
    
    print(f"  Hostname: {hostname}")
    print(f"  MAC: {mac}")
    print(f"  Vendor (local): {vendor}")
    print(f"  Open ports: {ports}")
    

if __name__ == "__main__":
#    load_oui('oui.txt')
#    test_single_ip('192.168.1.16')

     main()
