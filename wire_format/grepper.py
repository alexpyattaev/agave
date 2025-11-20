#!/usr/bin/env python3
import argparse
import numpy as np


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="data file path", type=str)
    parser.add_argument("slot", help="slot to locate", type=int)
    args = parser.parse_args()

    dtype = np.dtype(
        [
            ("time_stamp", "<u8"),
            ("slot_number", "<u8"),
            ("index", "<u4"),
            ("sender_ip", "<u4"),
            ("is_repair", "u1"),
        ]
    )
    arr = np.fromfile(args.path, dtype=dtype)
    arr = arr[arr["slot_number"] == args.slot]
    if len(arr) == 0:
        print("Not found")
        exit()
    np.save(f"{args.path}_{args.slot}", arr)


if __name__ == "__main__":
    main()
