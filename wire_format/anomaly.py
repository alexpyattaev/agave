from collections import defaultdict
from ipaddress import IPv4Address


def analyze_duplicates(duplicate_senders:dict[IPv4Address,int],gossip_state:dict[IPv4Address, dict] ):
    print("== Duplicate senders: top 10 ==")
    max_offenders = sorted(zip(duplicate_senders.values(), duplicate_senders.keys()), reverse=True)
    for dups, ip in max_offenders[:10]:
        row = f"IP:{ip}: {dups}"
        state = gossip_state.get(ip)
        if state is not None:
            row += f"(version:{state['version']} id: {state['identityPubkey']})"

        print(row)

    print("== Duplicates by version ==")

    # version -> total duplicates
    dups_by_version = defaultdict(int)
    for ip, dups in duplicate_senders.items():
        state = gossip_state.get(ip)
        if state is None:
            continue
        version = state.get("version")
        if version is None:
            continue
        dups_by_version[version] += dups

    # print grouped result
    for version, total_dups in sorted(dups_by_version.items(), key=lambda x: x[1], reverse=True):
        print(f"version: {version}: {total_dups}")


def analyze_late_shreds(too_late_shreds,gossip_state):
    print("==== TOO LATE ====")
    for (latency, shred) in too_late_shreds:
        state = gossip_state.get(shred.sender_ip)
        row = f"IP:{IPv4Address(shred.sender_ip)}: {latency}"
        if state is not None:
            row += f"(version:{state['version']} id: {state['identityPubkey']})"
        print(row)