import json
import psutil

PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def compare_rules(rule1, rule2):
    return str(rule1).strip() == str(rule2).strip()

def get_interfaces():
    addrs = psutil.net_if_addrs()
    interfaces = {}
    
    try:
        for key, addr_list in addrs.items():
            if key == "lo":
                continue
            
            interface_ip = '.'.join(addr_list[0].broadcast.split('.')[:-1] + ['0'])
            interfaces[key] = {
                "network": interface_ip,
                "ip": addr_list[0].address,
                "netmask": addr_list[0].netmask
            }
        return interfaces
    except AttributeError:
        print("Attribute error occurred while fetching interfaces.")
        return interfaces
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        exit()

def pprint(data):
    print(json.dumps(data, indent=2))

# Пример вызова функции
# pprint(get_interfaces())
