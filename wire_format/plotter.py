import pandas as pd
import matplotlib.pyplot as plt
import matplotlib as mpl
import argparse
import numpy as np
import matplotlib.dates as mdates

def parse_data(file_name:str, time_sample:int, start:int, end:int):
    columns = ["type", "slot ID", "Shred ID", "FEC ID", "FEC set size", "time_stamp"]
    start = max(start, 1) # skip header
    data = pd.read_csv(file_name, skiprows=range(0, start), sep=":", names=columns,
                        dtype={"type": str, "slot ID": int, "Shred ID": int, "FEC ID":int, "FEC set size":int, "time_stamp": str},
                        nrows=end - start)
    data["time_stamp"] = pd.to_numeric(data["time_stamp"], errors="coerce")
    data["time_stamp"] = pd.to_datetime(data["time_stamp"], unit="us", utc=True, errors="coerce")
    data["time_stamp"] = data["time_stamp"].dt.round(f"{time_sample}us")
    return data

def extract_block(data, block_idx:int):
    res = {}
    duplicate = {}
    block_df = data.loc[data["slot ID"] == block_idx]
    fec_ids = list(set(block_df["FEC ID"]))
    block_df.loc[:, "FEC ID"] = block_df["FEC ID"]
    for id in fec_ids:
        rcv_data = {}
        name = id
        res[name] = {}
        filtered = block_df.loc[block_df["FEC ID"] == id]
        total = 0
        for t in filtered["time_stamp"].unique():
            total += len(filtered.loc[block_df["time_stamp"] == t])
            res[name][t] = total
            for shred in filtered.loc[block_df["time_stamp"] == t].itertuples():
                if shred[3] not in rcv_data:
                    rcv_data[shred[3]] = [[],[],[]]
                rcv_data[shred[3]][0].append(shred[6]) #TIMESTAMP
                rcv_data[shred[3]][1].append(total) #CURRENT TOTAL
                rcv_data[shred[3]][2].append(shred[1]) #RECEIVE METHOD (REPAIR/TURBINE)
        for shred in rcv_data.keys():
            if len(rcv_data[shred][1]) > 1:
                duplicate[("|".join([str(shred),str([rcv_data[shred][2]])[3]]))] = [rcv_data[shred][0], rcv_data[shred][1]]

    return res, duplicate


def data_process(data, data_type):
    res = {}
    for block in data["slot number"].unique():
        name = " ".join([str(block),data_type])
        res[name] = {}
        filtered = data.loc[data["slot number"] == block]
        total = 0
        for t in filtered["time_stamp"].unique():
            total += len(filtered.loc[filtered["time_stamp"] == t])
            res[name][t] = total
    return res

def plot_shreds(ax, shreds_dict, duplicate):
    ax.clear()
    colors = mpl.color_sequences['Set1']
    max_y = 0

    for i, (fec_set_num, time_data) in enumerate(shreds_dict.items()):
        times = sorted(time_data.keys())  # Get timestamps in order
        counts = [time_data[t] for t in times]  # Get corresponding amounts
        ax.plot(times, counts, color=colors[i % len(colors)], alpha=1, linewidth=2)
        max_y = max(max_y, max(counts))
        ax.annotate(f'{fec_set_num}', xy=(times[-1], counts[-1]),
            rotation=90, xytext=(times[-1], counts[-1]+5),
                    arrowprops=dict(facecolor='white', headwidth=2, headlength=3, width=1),)

    #for i, (name,(timestamps, totals)) in enumerate(duplicate.items()):
    #    ax.scatter(timestamps, totals, color='red', alpha=1, s=35)
    #    for i in range(0,len(totals)):
    #        t = timestamps[i]
    #        total = totals[i]
    #        ax.annotate(f'{name}', xy=(t, total), xytext=(t, total + 3), ha='center', fontsize=9,rotation=90,
    #                    color='white', arrowprops=dict(facecolor='white', headwidth=2, headlength=3, width=1))

    ax.set_xlabel("Timestamp", fontsize=12, color="white")
    ax.set_ylabel("Count", fontsize=12, color="white")
    ax.set_ylim([0,max_y + 10])
    ax.tick_params(axis="x",rotation=45, color="white")
    ax.tick_params(axis="y", color="white")
    ax.grid(color="gray", linestyle="--", linewidth=0.5, alpha=0.5)


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
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help = "data file path", type=str)
    parser.add_argument("end_line", help = "last line that script reads", type=int)
    parser.add_argument("--start_line", help = "first line that script reads", type=int, default=0)
    parser.add_argument("--time_sample", help = "time sample in microseconds", type=int, default = 10000)
    args = parser.parse_args()
    data = parse_data(args.path, args.time_sample, args.start_line, args.end_line)
    plt.style.use("dark_background")
    fig, axes = plt.subplots(figsize=(12,6))

    #stamps = (data["time_stamp"].unique())
    #print(f"STAMPS:{stamps}")

    block_cursor = Cursor(sorted(pd.unique(data["slot ID"])))
    shreds_set, duplicate = extract_block(data, block_cursor.current())
    plot_shreds(axes, shreds_set, duplicate)
    def on_press(event):
        if event.key == 'right':
            block_cursor.next()
        elif event.key == "left":
            block_cursor.prev()
        elif event.key == "escape":
            exit()

        shreds_set, duplicate = extract_block(data, block_cursor.current())
        plot_shreds(axes, shreds_set, duplicate)
        fig.suptitle(f"Block number {block_cursor.current()}")
        fig.canvas.draw()

    fig.canvas.mpl_connect('key_press_event', on_press)
    plt.show()
    #shreds = data.loc[data["type"] == "SHRED_RX"]
    #stamps = (data["time_stamp"].unique())
    #print(f"STAMPS:{stamps}")
    #print("Shreds are separated...")
    #repair = data.loc[data["type"] == "REPAIR_RX"]
    #print("Repairs are separated...")
    #datasets = data_process(shreds, "shred")
    #print("Dataset: shreds added")
    #datasets.update(data_process(repair, "repair"))
    #print("Dataset: repairs added")
    #plot_datasets(datasets)
    return 0

if __name__ == "__main__":
    main()
