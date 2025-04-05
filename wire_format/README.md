=== Prerequisistes
You are on a host running solana validator, for example its gossip port is `11.12.13.14:8001`

=== Discover the ports of running validator
This is required for any monitor command!
``` cargo xtask run  -- discover  --gossip-addr 11.12.13.14:8001 ```

This will poke the specified validator over gossip to get shred_version,
TVU and TPU ports, and then will portscan to find repair traffic as well.
When done it will write results to a JSON file for later use.

=== Actual use
Remember that hitting Ctrl-C will always terminate the app gracefully, i.e. it will try to wait for a few seconds to do cleanup and flush files. If it times out, it will kill itself, no need to spam.

== Bitrate monitoring

```cargo xtask run  -- monitor bitrate gossip```
will show current bitrate of gossip broken down by CRDS type and message type

``` cargo xtask run  -- monitor bitrate turbine```
will show turbine bitrates broken down by shred types + repair bandwidth

== Metadata logging

``` cargo xtask run  --   monitor log-metadata turbine```
will log turbine (and repair) arrivals into a csv file for plotting

```python plotter.py ./monitor_data/time_log.csv 30000```
will then make nice interactive turbine delivery plots

== Gossip abusers
```cargo xtask run  -- monitor log-gossip-invalid-senders```
will look for suspicious gossip packets and log them for you
