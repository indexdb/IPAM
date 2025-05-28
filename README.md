
# IPAMScanner

https://github.com/phpipam/phpipam
phpIPAM is an open-source web IP address management application. 
However, its support for scanning hostnames, ports, and services is limited.
IPAMScanner compensates for this by scanning subnet hostnames and ports using multiple methods.
Currently, it operates by directly interacting with the database, though integration via API is also possible.


IPAMScanner works on Ubuntu,

Frist: download https://standards-oui.ieee.org/oui/oui.txt for offline MAC address Vendor matching.

Then, install dependencies:

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

---

![](docs/overview.png)
