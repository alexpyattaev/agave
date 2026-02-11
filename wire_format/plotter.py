#!/usr/bin/env python3
import json

import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt
import argparse
from collections import defaultdict, OrderedDict

from matplotlib.backend_bases import Event, MouseEvent
from matplotlib.widgets import CheckButtons
import numpy as np
from ipaddress import IPv4Address

from anomaly import analyze_duplicates, analyze_late_shreds

DEBUG_DUP_SENDERS = True

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


# Searches when batches for code block were ready to assemble
# Batch done when amount of unique shreds for one FEC Set  >= FEC ID Size/2
# Returns dict {FEC_SET_ID:TIME_STAMP}
def when_batch_done(shreds):
    done_stamps = {}
    block_times = []
    block_total_shreds = 0
    block_unique_shreds = 0
    block_batches = 0
    batch_size = 64

    for fec_id, group in shreds:
        group = group.sort_values("time_stamp")

        if not batch_size:
            continue

        total_shreds_received = group.shape[0]
        block_total_shreds += total_shreds_received
        block_batches += 1
        first_arrival = group.groupby("index")["time_stamp"].first()
        time_stamps = first_arrival.sort_values().tolist()
        block_unique_shreds += len(time_stamps)

        batch_time = (
            group["time_stamp"].iloc[-1] - group["time_stamp"].iloc[0]
        ) // 1000
        block_times.append(batch_time)

        required = batch_size // 2
        if len(time_stamps) >= required:
            done_stamps[fec_id] = time_stamps[required - 1]

    print(
        f"Block Time Statistics:\n- Batch average time: {(sum(block_times) / len(block_times)):.3f} ms"
        f"\n- Longest batch time: {max(block_times):.3f} ms"
        f"\n- Smallest batch time: {min(block_times):.3f} ms"
    )


def ready_indicator(dct, shreds_set):
    indicators = {}
    for id, time_stamp in dct.items():
        indicators[time_stamp] = shreds_set[id][time_stamp]
    return indicators


def extract_block(block_df, leader_schedule:dict, gossip_state:dict) -> pd.DataFrame:
    # tracks the process of FEC set building
    shreds = defaultdict(list)
    # tracks times of arrivals for all duplicates
    duplicates = defaultdict(list)
    # tracks timestamps of multicast arrivals for a given FEC set
    multicasts = defaultdict(list)
    # tracks timestamps of multicast arrivals for a given FEC set
    repairs = defaultdict(list)

    block_df.loc[:, "fec_index"] = block_df["index"] // 64
    grouped_by_fec = block_df.groupby("fec_index")
    fec_set_indices = pd.unique(block_df["fec_index"])
    fec_set_completion_stats = []
    duplicate_senders = defaultdict(int)
    too_late_shreds = []
    first_shred_timestamp = block_df['time_stamp'].min()
    for fec_id, group in grouped_by_fec:
        group = group.sort_values("time_stamp")
        # tracks which indices we have received, and records the row number for them
        received_indices: OrderedDict[int, int] = OrderedDict()
        received_indices_multicast: OrderedDict[int, int] = OrderedDict()
        for shred in group.itertuples():
            if shred.is_multicast:
                received_indices_multicast[shred.index] = shred.Index
                multicasts[fec_id].append(
                    (shred.time_stamp, len(received_indices_multicast))
                )
                continue
            if shred.index in received_indices:
                base_shred_time = group.loc[received_indices[shred.index], "time_stamp"]
                base_shred_y = list(received_indices.keys()).index(shred.index)
                #print("dup", base_shred_time, base_shred_y)
                duplicates[fec_id].append((base_shred_time, base_shred_y))

                duplicate_senders[IPv4Address( shred.sender_ip)]+=1
            else:
                received_indices[shred.index] = shred.Index
            latency = (shred.time_stamp - first_shred_timestamp) / 1000
            if latency > 400:
                too_late_shreds.append((latency, shred))
            y = len(received_indices)
            shreds[fec_id].append((shred.time_stamp, y))

            if shred.is_repair:
                repairs[fec_id].append((shred.time_stamp, y))
        fec_set_completion_stats.append(len(received_indices.keys()))

    def total_shreds(x) -> int:
        return sum([len(fs) for fs in multicasts.values()])



    print(
        f"Block Data Statistics:\n- FEC set count: {len(shreds)}"
        f"\n- Unicast shreds: {total_shreds(shreds)}"
        f"\n- Multicast shreds: {total_shreds(multicasts)}"
        f"\n- Unique unicast shreds: {total_shreds(shreds) - total_shreds(duplicates)}"
        f"\n- Duplicate unicast shreds: {total_shreds(duplicates)}"
        f"\n- Shreds per FEC set: E={np.mean(fec_set_completion_stats)} median={np.median(fec_set_completion_stats)}"
        f"\n- Repair shreds in block: {total_shreds(repairs)}"

    )

    if DEBUG_DUP_SENDERS:
        analyze_duplicates(duplicate_senders, gossip_state)

    analyze_late_shreds(too_late_shreds, gossip_state)

    sources = {
        "shreds": shreds,
        "duplicates": duplicates,
        "repairs": repairs,
        "multicasts": multicasts,
    }
    rows = {}

    for fec_set_index in fec_set_indices:
        row = {}
        for name, data in sources.items():
            data = data[fec_set_index]
            if not data:
                x = []
                y = []
            else:
                x = [d[0] for d in data]
                y = [d[1] for d in data]
            row[(name, "times")] = x
            row[(name, "counts")] = y
        rows[fec_set_index] = row
    df = pd.DataFrame(rows).sort_index()
    return df


def plot_shreds(
    ax,
    block_df,
    show_repair=True,
    show_duplicate=True,
):
    ax.clear()
    colors = mpl.color_sequences["Set1"]
    max_y = 0
    zero_time = min(block_df.loc["shreds"].loc["times"].min())
    # from ipaddress import IPv4Address
    # late = df.loc[(df["time_stamp"] - zero_time) > 400000]
    # for row in late.loc[:, ["time_stamp", "sender_ip"]].itertuples(index=False):
    #     ip = IPv4Address(row.sender_ip)
    #     print(f"""delay: {(row.time_stamp - zero_time) / 1000} ip {ip}""")

    # plot FEC set
    shreds = block_df.loc["shreds"]
    for fec in shreds.columns:
        counts = shreds.at["counts", fec]
        times = shreds.at["times", fec]
        t_ms = (np.array(times) - zero_time) / 1000.0
        ax.plot(
            t_ms,
            counts,
            color=colors[fec % len(colors)],
            alpha=1,
            linewidth=2,
            label=f"FEC {fec}",
        )

    shreds = block_df.loc["multicasts"]
    for fec in shreds.columns:
        counts = shreds.at["counts", fec]
        times = shreds.at["times", fec]
        t_ms = (np.array(times) - zero_time) / 1000.0
        label = "Multicast" if fec == 0 else "_nolegend mcast_"
        ax.plot(
            t_ms,
            counts,
            color=colors[fec % len(colors)],
            alpha=1,
            linewidth=2,
            linestyle=":",
            label=label,
        )
    # plot batch is ready marks
    # if ready_indicators:
    #     done_times = [(ts - zero_time) // 1000 for ts in ready_indicators.keys()]
    #     done_counts = list(ready_indicators.values())
    #     ax.scatter(
    #         done_times,
    #         done_counts,
    #         color="green",
    #         alpha=1,
    #         s=80,
    #         marker="X",
    #         label="Batch Done",
    #     )

    # plot repair shreds
    if show_repair:
        repairs = block_df.loc["repairs"]
        for fec in repairs.columns:
            counts = repairs.at["counts", fec]
            times = repairs.at["times", fec]
            t_ms = (np.array(times) - zero_time) / 1000.0
            if counts is not None:
                label = "Repair" if fec == 0 else "_nolegend repair_"
                ax.scatter(t_ms, counts, marker="o", color="orange", s=30, label=label)
    # plot duplicates
    if show_duplicate:
        duplicates = block_df.loc["duplicates"]
        for fec in duplicates.columns:
            counts = duplicates.at["counts", fec]
            times = duplicates.at["times", fec]
            t_ms = (np.array(times) - zero_time) // 1000
            label = "Duplicates" if fec == 0 else "_nolegend dup_"
            ax.scatter(t_ms, counts, color="red", marker="+", s=25, label=label)

    # some labels
    ax.set_xlabel("Time since first shred (ms)", fontsize=12, color="white")
    ax.set_ylabel("Shred count", fontsize=12, color="white")
    ax.set_ylim([0, 70])
    ax.set_xlim([-20, 500])
    ax.set_yticks(np.arange(0, 70, 8))
    ax.tick_params(axis="x", rotation=45, color="white")
    ax.tick_params(axis="y", color="white")
    ax.grid(color="gray", linestyle="--", linewidth=0.5, alpha=0.5)
    ax.legend(
        fontsize=8, loc="upper left", bbox_to_anchor=(1.0, 1.0), borderaxespad=0.0
    )


# cursor class for navigation thorugh blocks
class Cursor:
    def __init__(self, data, index=0):
        self.data = data
        self.index = index

    def next(self) -> pd.DataFrame:
        if self.index < len(self.data) - 1:
            self.index += 1
        return self.current()

    def prev(self):
        if self.index >= 1:
            self.index -= 1
        return self.current()

    def current(self):
        return self.data[self.index]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="data file path", type=str)
    parser.add_argument("slot", help="start at given slot",nargs="?", type=int, default=None)
    parser.add_argument("--leader_schedule", help="file with leader schedule (json)",
                        type=str, default=None)
    parser.add_argument("--gossip_state", help="file with gossip state (json)",
                        type=str, default=None)
    args = parser.parse_args()

    leader_schedule = {}
    if args.leader_schedule is not None:
        with open(args.leader_schedule, "r") as f:
            leader_schedule = json.load(f)['leaderScheduleEntries']
            leader_schedule = {ls['slot']: ls['leader'] for ls in leader_schedule}

    gossip_state = {}
    if args.gossip_state is not None:
        with open(args.gossip_state, "r") as f:
            for row in json.load(f):
                # store same value using both IP address and pubkey
                # to save sanity when passing this around
                gossip_state[IPv4Address(row["ipAddress"])] = row
                gossip_state[row['identityPubkey']] = row
    data = parse_data(args.path)
    all_slots = sorted(pd.unique(data["slot_number"]))
    start_index = all_slots.index(args.slot) if args.slot is not None else 0
    cursor = Cursor(all_slots, start_index)
    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(12, 6))

    check_ax = plt.axes((0.01, 0.8, 0.08, 0.1))
    visibility_options = {"Repair": True, "Duplicate": True}

    check = CheckButtons(
        check_ax,
        list(visibility_options.keys()),
        list(visibility_options.values()),
        check_props={"color": "white"},
        frame_props={"edgecolor": "white"},
    )

    def render():
        slot_id = int(cursor.current())
        leader_id = leader_schedule.get(slot_id)

        leader_info = ""
        if leader_id is not None:
            leader_info += f" {leader_id}"
            gossip_info = gossip_state.get(leader_id)
            if gossip_info is not None:
                leader_info+= f" {gossip_info['ipAddress']} {gossip_info['version']}"
        title = f"Block number {slot_id} {leader_info}"
        print(title)
        block_df = data.loc[data["slot_number"] == slot_id].copy()

        block_df = extract_block(block_df, leader_schedule, gossip_state)
        # done_batches = when_batch_done(df)

        plot_shreds(
            ax,
            block_df,
            show_repair=visibility_options["Repair"],
            show_duplicate=visibility_options["Duplicate"],
        )

        fig.suptitle(
            title,
            fontsize=14,
            color="white",
        )
        fig.canvas.draw()

    def check_toggle(label):
        visibility_options[label] = not visibility_options[label]
        render()

    def on_press(event)->None:
        if event.key == "right":
            cursor.next()
        elif event.key == "left":
            cursor.prev()
        elif event.key == "escape":
            exit()

        render()

    check.on_clicked(check_toggle)
    def on_mouse_move(event:MouseEvent)->None:
        #print(event.xdata, event.ydata)
        pass

    fig.canvas.mpl_connect("motion_notify_event", on_mouse_move)
    fig.canvas.mpl_connect("key_press_event", on_press)
    render()
    plt.show()


if __name__ == "__main__":
    main()
