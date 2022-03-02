# Your system should have installed idstools from Python 3 packages. Check the description for how to install it.
from idstools import rule


def parse():
    filename="community-rules/community.rules"
    ordered_class_types = [
        "attempted-admin",
        "attempted-user",
        "inappropriate-content",
        "policy-violation",
        "shellcode-detect",
        "successful-admin",
        "successful-user",
        "trojan-activity",
        "unsuccessful-user",
        "web-application-attack",
        "attempted-dos",
        "attempted-recon",
        "bad-unknown",
        "default-login-attempt",
        "denial-of-service",
        "misc-attack",
        "non-standard-protocol",
        "rpc-portmap-decode",
        "successful-dos",
        "successful-recon-largescale",
        "successful-recon-limited",
        "suspicious-filename-detect",
        "suspicious-login",
        "system-call-detect",
        "unusual-client-port-connection",
        "web-application-activity",
        "icmp-event",
        "misc-activity",
        "network-scan",
        "not-suspicious",
        "protocol-command-decode",
        "string-detect",
        "unknown",
        "tcp-connection"
    ]

    for i,c in enumerate(ordered_class_types):
        rule_list = []
        for r in rule.parse_file(filename):
            if r.classtype == c:
                rule_list.append(f"{r.gid}:{r.sid}")
        rule_list_str = "\n".join(rule_list)
        with open(f'{i}_{c}.txt', 'w') as f:
            f.write(rule_list_str)


if __name__ == '__main__':
    parse()