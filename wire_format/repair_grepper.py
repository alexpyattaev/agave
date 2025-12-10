#!/usr/bin/env python3
import argparse
from collections import OrderedDict, defaultdict

import numpy as np
import pandas as pd


def parse_data(file_name: str):
    # if we are given npy file produced by grepper
    if file_name.endswith("npy"):
        arr = np.load(file_name)
    else:
        # if we are given raw binary file
        dtype = np.dtype(
            [
                ("time_stamp", "<u8"),
                ("slot_number", "<u8"),
                ("index", "<u4"),
                ("sender_ip", "<u4"),
                ("flags", "u1"),
            ]
        )
        arr = np.fromfile(file_name, dtype=dtype)

    data = pd.DataFrame(arr)
    data["is_repair"] = np.array(arr["flags"] & 0b0001, dtype=bool)
    data["is_multicast"] = np.array(arr["flags"] & 0b0010, dtype=bool)

    return data


def ready_indicator(dct, shreds_set):
    indicators = {}
    for id, time_stamp in dct.items():
        indicators[time_stamp] = shreds_set[id][time_stamp]
    return indicators


def block_has_useful_repairs(block_df) -> bool:
    # tracks the process of FEC set building
    shreds = defaultdict(list)
    # tracks times of arrivals for all duplicates
    duplicates = defaultdict(list)

    block_df.loc[:, "fec_index"] = block_df["index"] // 64
    grouped_by_fec = block_df.groupby("fec_index")

    for fec_id, group in grouped_by_fec:
        group = group.sort_values("time_stamp")
        # tracks which indices we have received, and records the row number for them
        received_indices: OrderedDict[int, int] = OrderedDict()
        for shred in group.itertuples():
            if shred.is_multicast:
                # explicitly ignore multicast as it is not useful for repair debug purposes
                continue
            if shred.index in received_indices:
                base_shred_time = group.loc[received_indices[shred.index], "time_stamp"]
                base_shred_y = list(received_indices.keys()).index(shred.index)
                duplicates[fec_id].append((base_shred_time, base_shred_y))
            else:
                received_indices[shred.index] = shred.Index

            y = len(received_indices)
            shreds[fec_id].append((shred.time_stamp, y))

            if shred.is_repair:
                if len(received_indices) < 32:
                    return True

    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="data file path", type=str)
    parser.add_argument(
        "slot", help="start at given slot", nargs="?", type=int, default=None
    )
    args = parser.parse_args()

    data = parse_data(args.path)
    all_slots = sorted(pd.unique(data["slot_number"]))
    start_index = all_slots.index(args.slot) if args.slot is not None else 0

    found = []
    for slot_id in all_slots:
        print(f"Slot ID: {slot_id} ")
        block_df = data.loc[data["slot_number"] == slot_id].copy()

        if block_has_useful_repairs(block_df):
            found.append(slot_id)

        if len(found) > 100:
            break
    print("Found useful repairs:")
    print(found)


if __name__ == "__main__":
    main()
