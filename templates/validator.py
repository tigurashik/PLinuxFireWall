import csv

def compare_rules(primary_rule: str, secondary_rules: list) -> bool:
    primary_rule = primary_rule.strip()
    return any(primary_rule == rule.strip() for rule in secondary_rules)

def validate_with_route_table(src_addr: str, dst_addr: str, src_port: int, dst_port: int) -> bool:
    try:
        with open("./imports/Rules.csv", "r") as rules_stream:
            rules = csv.reader(rules_stream)

            for rule in rules:
                # <SRC_IP> <SRC_PORT> <DST_IP> <DST_PORT>
                # Check for IP
                if (compare_rules(rule[1], [src_addr, dst_addr, "any"]) and
                        compare_rules(rule[3], [dst_addr, src_addr, "any"])):
                    # Check for port
                    if (compare_rules(rule[2], [src_port, "any", 0]) and
                            compare_rules(rule[4], [dst_port, "any", 0])):
                        action = str(rule[0]).lower()
                        if action == "allow":
                            return True
                        elif action in ["deny", "disable"]:
                            continue
            return False
    except Exception as e:
        print(f"[ERR] Error reading rules: {e}")
        return False

# Примеры вызова функции
# print(validate_with_route_table("0.0.0.0", "127.0.0.0", 22, 22))
# print(validate_with_route_table("192.168.2.100", "192.168.1.100", 22, 0))
# print(validate_with_route_table("192.168.2.100", "100", 80, 90))
