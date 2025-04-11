=== Prerequisistes
You are on a host running solana validator, for example its gossip port is `11.12.13.14:8001`
You have bpf-linker installed. If not `cargo install bpf-linker`.

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


== Reporting metrics / unattended mode

```SOLANA_METRICS_CONFIG="host=https://internal-metrics.solana.com:8086,db=<database>,u=<user>,p=<password>" cargo xtask run --  monitor bitrate --report-metrics gossip```
will report metrics into influxdb rather than showing GUI

== Working with doublezero

running with `--strip-gre` will attach to provided interface and strip GRE headers to get to the actual packets. So, on a doublezero host:
```cargo xtask run -- --strip-gre --interface=<actual_eth_ip> discover --gossip-addr <dz_ip_addr>:8001```
and then to actually run monitor:
```cargo xtask run -- --strip-gre --interface=<actual_eth_ip> monitor bitrate gossip```
