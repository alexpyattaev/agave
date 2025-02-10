#!/usr/bin/python

import csv

input_file = 'monitor_data/time_log.csv'
fieldnames = ['event_type', 'slot_number', 'index', 'fec_index', 'sender_ip', 'us_since_epoch']


target_ips = {'64.130.43.178':0,'64.130.42.163':1}
message_times= [dict(), dict()]

# Open and parse the file
with open(input_file, 'r', newline='') as f:
    reader = csv.DictReader(f, delimiter=':',fieldnames=fieldnames)

    for row in reader:
        # Each row is a dictionary with keys:
        # 'event_type', 'slot_number', 'index', 'fec_index', 'sender_ip', 'us_since_epoch'
        sender_ip = row['sender_ip']
        num_of_sender = target_ips.get(sender_ip)
        if num_of_sender is None:
            continue  # skip irrelevant IPs

        index = int(row['index'])
        slot = int(row['slot_number'])
        key = (slot, index)
        timestamp = int(row['us_since_epoch'])

        # maybe only record the first time we saw a message from this sender for a given key?
        message_times[num_of_sender][key] = timestamp

all_keys = set(message_times[0].keys()).union( message_times[1].keys())
all_keys = sorted(all_keys)

got = 0
lost_0 = 0
lost_1 = 0
lead_0 = 0
lead_1 = 0

for key in all_keys:

    time_0 = message_times[0].get(key)
    time_1 = message_times[1].get(key)
    if time_0 is None:
        lost_0 += 1
        continue
    if time_1 is None:
        lost_1 += 1
        continue
    got += 1 
    diff = time_0 - time_1
    if diff > 0 : # 0 is slower than 1
        lead_1 += diff
    else:
        lead_0 += -diff

print(f"IP addresses are {target_ips}")
print(f"Captured {got} shreds, missing packets from 0:{lost_0} 1:{lost_1}, timing lead: 0:{lead_0}us 1:{lead_1}us")
