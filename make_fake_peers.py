#!/usr/bin/env python3
"""Generate a fake_peers.json file for use with --fake-peers-file.

Each peer gets a freshly generated keypair (via solana-keygen), a stake
amount, and a set of socket addresses derived from a single IP and a
base port.  All peers share the same IP by default; ports advance by 30
per peer so that the full new_with_socketaddr layout fits within each
peer's range.

JSON output format (per-peer):
  {
    "keypair": [<64 u8 values>],
    "stake_lamports": <u64>,
    "ip": "<IPv4 string>",
    "base_port": <u16>
  }
"""
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Tuple


def _gen_keypair() -> Tuple[str, List[int]]:
    """Run solana-keygen, return (pubkey_b58, keypair_bytes_as_list)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = Path(f.name)
    try:
        result = subprocess.run(
            f"solana-keygen new --no-passphrase --force --outfile {tmp}",
            check=True,
            capture_output=True,
            text=True,
            shell=True
        )
        pubkey: str | None = None
        for line in result.stdout.splitlines():
            if line.startswith("pubkey:"):
                pubkey = line.split("pubkey:", 1)[1].strip()
                break
        if not pubkey:
            raise RuntimeError("solana-keygen output missing 'pubkey:' line")
        keypair_bytes: List[int] = json.loads(tmp.read_text())
        if len(keypair_bytes) != 64:
            raise ValueError(f"Expected 64 bytes, got {len(keypair_bytes)}")
        return pubkey, keypair_bytes
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate fake_peers.json for --fake-peers-file"
    )
    parser.add_argument("--count", type=int, default=10, help="Number of fake peers")
    parser.add_argument(
            "--ip", default="127.0.0.1", help="Shared IP for all peers"
    )
    parser.add_argument(
        "--base-port",
        type=int,
        default=8100,
        help="Starting base port; increments by 30 per peer",
    )
    parser.add_argument(
        "--stake-lamports",
        type=int,
        default=1,
        help="Stake in lamports for each peer",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/home/sol/fake_peers.json"),
        help="Output file path",
    )
    args = parser.parse_args()

    peers = []
    port = args.base_port
    for i in range(args.count):
        pubkey, keypair_bytes = _gen_keypair()
        peers.append(
            {
                "keypair": keypair_bytes,
                "stake_lamports": args.stake_lamports,
                "ip": args.ip,
                "base_port": port,
            }
        )
        port += 30
        print(f"  [{i+1}/{args.count}] {pubkey} @ {args.ip}:{port - 30}")

    output = {"peers": peers}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w") as f:
        json.dump(output, f)
    print(f"Written {args.count} peers to {args.output}")


if __name__ == "__main__":
    main()
