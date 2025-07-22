import re
import requests

URLS = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
    "https://badmojr.gitlab.io/1hosts/Pro/unbound.conf",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/unbound/dyndns.blacklist.conf",
    "https://oooo.b-cdn.net/blahdns/blahdns_unbound.conf",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=unbound&showintro=0",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate.txt",
    "https://raw.githubusercontent.com/mr-narender/domain_filter/refs/heads/main/for_ad_blocklist.txt",
    "https://raw.githubusercontent.com/ph00lt0/blocklists/master/unbound-blocklist.txt",
    "https://raw.githubusercontent.com/r0xd4n3t/pihole-adblock-lists/main/pihole_adlists.txt"
]

domain_pattern = re.compile(
    r"""
    (?:
        local-zone:\s*"(?P<lz>[^"]+)"     # local-zone: "domain"
        |@@?(?:\|\|)?(?P<adg>[\w.-]+\.\w+)# ||domain^ or @@domain^
        |\*\.(?P<wc>[\w.-]+\.\w+)         # *.domain
        |(?P<raw>\b[\w.-]+\.\w+\b)        # plain domain
    )
    """,
    re.VERBOSE
)

seen = set()

def extract_domains(text):
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for match in domain_pattern.finditer(line):
            domain = next(g for g in match.groups() if g)
            domain = domain.strip('.').lower()
            if domain:
                domains.add(domain)
    return domains

for url in URLS:
    try:
        print(f"Fetching {url}")
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        seen |= extract_domains(resp.text)
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")

final = sorted(seen)
with open("blocklist.txt", "w") as f:
    for domain in final:
        f.write(f'local-zone: "{domain}" always_nxdomain\n')
