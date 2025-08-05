#!/usr/bin/python

import csv

input_file = 'monitor_data/time_log.csv'
fieldnames = ['event_type', 'slot_number', 'index', 'fec_index', 'sender_ip', 'us_since_epoch']


target_ips = {'192.168.1.10':0,'192.168.1.11':1}
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

lost_a = 0
lost_b = 0
lead_a = 0
lead_b = 0

for key in all_keys:

    a_time = message_times[0].get(key)
    b_time = message_times[1].get(key)
    if a_time is None:
        lost_a += 1
        continue
    if b_time is None:
        lost_b += 1
        continue

    diff = a_time - b_time
    if diff > 0 : # a is slower than b
        lead_b += diff
    else:
        lead_a += -diff

print(f"{lost_a=} {lost_b=} {lead_a=} {lead_b=}")
