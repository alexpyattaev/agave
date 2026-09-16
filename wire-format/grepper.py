#!/usr/bin/env python3
import argparse
import numpy as np


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="data file path", type=str)
    parser.add_argument("slot_min", help="first slot to locate", type=int)
    parser.add_argument("slot_max", help="last slot to locate", type=int)
    args = parser.parse_args()

    dtype = np.dtype(
        [
            ("time_stamp", "<u8"),
            ("slot_number", "<u8"),
            ("index", "<u4"),
            ("sender_ip", "<u4"),
            ("flags", "u1"),
        ]
    )
    arr = np.fromfile(args.path, dtype=dtype)

    arr = arr[
        (args.slot_min <= arr["slot_number"]) * (arr["slot_number"] <= args.slot_max)
    ]
    if len(arr) == 0:
        print("Not found")
        exit()
    np.save(f"grepped_{args.slot_min}_{args.slot_max}", arr)


if __name__ == "__main__":
    main()
