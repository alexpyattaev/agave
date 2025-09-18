import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt
import argparse
import io
from matplotlib.widgets import Button
from collections import defaultdict
from matplotlib.widgets import CheckButtons

def index_slots_by_byte_ranges(file_path):
    slot_map = {}
    with open(file_path, 'rb') as f:
        current_pos = f.tell()
        line = f.readline()
        while line:
            next_pos = f.tell()
            decoded = line.decode(errors='ignore').strip()
            #print(f"Processing line at byte position {current_pos} to {next_pos}: {decoded}")

            if not decoded or ":" not in decoded:
                line = f.readline()
                current_pos = next_pos
                continue

            parts = decoded.split(":")

            try:
                slot_id = int(parts[1])
                #print(f"Extracted slot ID: {slot_id} from line: {decoded}")
            except ValueError:
                line = f.readline()
                current_pos = next_pos
                continue

            if slot_id not in slot_map:
                slot_map[slot_id] = [current_pos, next_pos]
            else:
                slot_map[slot_id][1] = current_pos

            line = f.readline()
            current_pos = next_pos

    return slot_map

def read_slot_data_by_bytes(file_path, byte_range, target):
    with open(file_path, 'rb') as f:
        f.seek(byte_range[0])
        chunk = f.read(byte_range[1] - byte_range[0]).decode(errors='ignore')
        columns = ["type", "slot ID", "Shred ID", "FEC ID", "Sender", "time_stamp"]
        df = pd.read_csv(io.StringIO(chunk), sep=":", names=columns,
                         dtype={"type": str, "slot ID": int, "Shred ID": int, "FEC ID":int,
                                "Sender":str , "time_stamp": int})
        df["time_stamp"] = pd.to_datetime(pd.to_numeric(df["time_stamp"], errors="coerce"), unit="us", utc=True)
        filtered_df = df[df["slot ID"] == target]
        return filtered_df

# Searches when batches for code block were ready to assemble
# Batch done when amount of unique shreds for one FEC Set  >= FEC ID Size/2
# Returns dict {FEC_SET_ID:TIME_STAMP}
def when_batch_done(block_df):
    done_stamps = {}
    block_times = []
    block_total_shreds = 0
    block_unique_shreds = 0
    block_batches = 0
    batch_size = 64

    try:
        repairs = block_df.loc[block_df["type"] == "REPAIR"].shape[0]

        grouped = block_df.groupby("FEC ID")

        for fec_id, group in grouped:
            group = group.sort_values("time_stamp")

            if not batch_size:
                continue

            total_shreds_received = group.shape[0]
            block_total_shreds += total_shreds_received
            block_batches += 1
            first_arrival = group.groupby("Shred ID")["time_stamp"].first()
            time_stamps = first_arrival.sort_values().tolist()
            block_unique_shreds += len(time_stamps)

            batch_time = (group["time_stamp"].iloc[-1] - group["time_stamp"].iloc[0]).total_seconds() * 1000
            block_times.append(batch_time)

            required = (batch_size // 2)
            if len(time_stamps) >= required:
                done_stamps[fec_id] = time_stamps[required - 1]

        print(f"Block Time Statistics:\n- Batch average time: {(sum(block_times) / len(block_times)):.3f} ms"
              f"\n- Longest batch time: {max(block_times):.3f} ms"
              f"\n- Smallest batch time: {min(block_times):.3f} ms")
        print(f"Block Data Statistics:\n- Batch count: {block_batches}"
              f"\n- Total shreds received: {block_total_shreds}"
              f"\n- Unique shreds received: {block_unique_shreds}"
              f"\n- Duplicate shreds: {block_total_shreds - block_unique_shreds}"
              f"\n- Repair shreds in block: {repairs}")

    except Exception as e:
        print("Some error happened...", e)
    finally:
        return done_stamps

def ready_indicator(dct, shreds_set):
    indicators = {}
    for id, time_stamp in dct.items():
        indicators[time_stamp] = shreds_set[id][time_stamp]
    return indicators

def extract_block(block_df):
    shreds = defaultdict(dict)
    duplicate = {}

    grouped_by_fec = block_df.groupby("FEC ID")

    for fec_id, group in grouped_by_fec:
        group = group.sort_values("time_stamp")
        rcv_data = {}
        total = 0

        grouped_by_time = group.groupby("time_stamp")

        for time, time_group in grouped_by_time:
            time_shred_ids = time_group["Shred ID"].tolist()
            duplicates_count = 0

            for shred_id in time_shred_ids:
                if shred_id in rcv_data:
                    duplicates_count += 1
                else:
                    rcv_data[shred_id] = [[], [], []]

            total += (len(time_shred_ids) - duplicates_count)
            shreds[fec_id][time] = total

            for _, row in time_group.iterrows():
                shred_id = row["Shred ID"]
                if shred_id in rcv_data:
                    rcv_data[shred_id][0].append(row["time_stamp"])
                    rcv_data[shred_id][1].append(total)
                    rcv_data[shred_id][2].append(row["type"])

        # count duplicates
        for shred_id, (timestamps, totals, methods) in rcv_data.items():
            if len(totals) > 1:
                name = f"{shred_id}|{str(methods)[:3]}"
                duplicate[name] = [timestamps, totals]

    return dict(shreds), duplicate

def plot_shreds(df, ax, shreds_dict, duplicate, ready_indicators, show_repair=True, show_duplicate=True):
    ax.clear()
    colors = mpl.color_sequences['Set1']
    max_y = 0

    try:
        zero_time = min(min(times.keys()) for times in shreds_dict.values())
    except ValueError:
        return

    # plot FEC set
    for i, (fec_set_num, time_data) in enumerate(shreds_dict.items()):
        times = sorted(time_data.keys())
        deltas = [(t - zero_time).total_seconds() * 1000 for t in times]
        counts = [time_data[t] for t in times]

        ax.plot(deltas, counts, color=colors[i % len(colors)], alpha=1, linewidth=2, label=f"FEC {fec_set_num//32}")
        max_y = max(max_y, counts[-1])

    # plot batch is ready marks
    if ready_indicators:
        done_times = [(ts - zero_time).total_seconds() * 1000 for ts in ready_indicators.keys()]
        done_counts = list(ready_indicators.values())
        ax.scatter(done_times, done_counts, color='green', alpha=1, s=80, marker='X', label="Batch Done")

    # plot repair shreds
    if show_repair:
        repair_df = df[df["type"] == "REPAIR"]
        for i, (_, row) in enumerate(repair_df.iterrows()):
            t = row["time_stamp"]
            t_ms = (t - zero_time).total_seconds() * 1000
            y = shreds_dict.get(row["FEC ID"], {}).get(t, None)
            if y is not None:
                label = "Repair Shred" if i == 0 else "_nolegend_"
                ax.scatter(t_ms, y, marker='o', color='orange', s=30, label=label)
    # plot duplicates
    if show_duplicate and duplicate:
        dup_x, dup_y = [], []
        for timestamps, totals in duplicate.values():
            dup_x.extend([(t - zero_time).total_seconds() * 1000 for t in timestamps])
            dup_y.extend(totals)
        ax.scatter(dup_x, dup_y, color='red', marker="+", s=25, label="Duplicates")

    # some labels
    ax.set_xlabel("Time since first shred (ms)", fontsize=12, color="white")
    ax.set_ylabel("Shred count", fontsize=12, color="white")
    ax.set_ylim([0, max_y + 5])
    ax.tick_params(axis="x", rotation=45, color="white")
    ax.tick_params(axis="y", color="white")
    ax.grid(color="gray", linestyle="--", linewidth=0.5, alpha=0.5)
    ax.legend(fontsize=8, loc='upper left', bbox_to_anchor=(1,1), borderaxespad=0.)

# cursor class for navigation thorugh blocks
class Cursor:
    def __init__(self, data):
        self.data=data
        self.index = 0

    def next(self):
        if self.index < len(self.data)-1:
            self.index += 1
        return self.current()

    def prev(self):
        if self.index >= 1:
            self.index -= 1
        return self.current()

    def current(self):
        return self.data[self.index]

def main():
    current_filter = {"type": "ALL"}
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help = "data file path", type=str)
    args = parser.parse_args()

    file_path = args.path

    print("Indexing slot byte ranges...")
    slot_map = index_slots_by_byte_ranges(file_path)
    slot_ids = sorted(slot_map.keys())

    cursor = Cursor(slot_ids)
    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(12, 6))

    check_ax = plt.axes([0.01, 0.8, 0.08, 0.1])
    visibility_options = {
        "Repair": True,
        "Duplicate": True
    }

    check = CheckButtons(check_ax,
                         list(visibility_options.keys()),
                         list(visibility_options.values()),
                         check_props={"color": "white"},
                         frame_props={"edgecolor": "white"})

    def render():
        slot_id = cursor.current()
        print(f"Slot ID: {slot_id} ")
        byte_range = slot_map[slot_id]

        df = read_slot_data_by_bytes(file_path, byte_range, slot_id)

        if current_filter["type"] == "REPAIR":
            df = df[df["type"] == "REPAIR"]
        elif current_filter["type"] == "SHRED":
            df = df[df["type"] == "SHRED"]

        shreds, duplicates = extract_block(df)
        done_batches = when_batch_done(df)
        ready_indicators = ready_indicator(done_batches, shreds)

        plot_shreds(df, ax, shreds, duplicates, ready_indicators,
                    show_repair=visibility_options["Repair"],
                    show_duplicate=visibility_options["Duplicate"])

        fig.suptitle(f"Block number {cursor.current()} - Showing {current_filter['type']} shreds", fontsize=14, color="white")
        fig.canvas.draw()

    def check_toggle(label):
        visibility_options[label] = not visibility_options[label]
        render()

    def on_press(event):
        if event.key == 'right':
            cursor.next()
        elif event.key == 'left':
            cursor.prev()
        elif event.key == 'escape':
            exit()
        render()

    check.on_clicked(check_toggle)

    fig.canvas.mpl_connect('key_press_event', on_press)
    render()
    plt.show()

if __name__ == "__main__":
    main()
