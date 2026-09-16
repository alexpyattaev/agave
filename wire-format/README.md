### Prerequisistes

You are on a host running solana validator, for example its gossip port is `11.12.13.14:8001`
You have bpf-linker installed. If not `cargo install bpf-linker`. This also pretty much
requires a decently new kernel from 6.0 branch at least to work correctly.

Python plotting scripts require ```python3 python3-matplotlib python3-numpy python3-pandas```

Cargo xtask will use sudo to run the commands as root.

### Discover the ports of running validator

This is required for any monitor command!
``` cargo xtask run  -- discover  --gossip-addr 11.12.13.14:8001 ```

This will poke the specified validator over gossip to get shred_version,
TVU and TPU ports, and then will portscan to find repair traffic as well.
When done it will write results to a JSON file `.wire_format.json`.

This might fail to find repair traffic (if there are no repairs coming in),
in this case it will leave a gap in the JSON file, and turbine capture will
not work correctly.

In this case you can open validator log and grep for the port bindings to fill it in
manually with:

```bash
rg -A 300 "as follows" agave-validator.log
```

### Actual use

Remember that hitting Ctrl-C will always terminate the app gracefully, i.e. it will
try to wait for a few seconds to do cleanup and flush files.

## Inbound vs outbound

Most (not all) commands support operation in either direction. Supply the `--direction` argument to
specify, inbound is the default. Capture in both directions at once is under development. For example,
``` cargo xtask run  -- monitor --direction=outbound bitrate turbine```
will show turbine bitrates for outbound traffic.

## Bitrate monitoring

```cargo xtask run  -- monitor bitrate gossip```
will show current bitrate of gossip broken down by CRDS type and message type

``` cargo xtask run  -- monitor bitrate turbine```
will show turbine bitrates broken down by shred types + repair bandwidth


## Metadata logging

``` cargo xtask run  --   monitor log-metadata turbine```
will log turbine (and repair) arrivals into a binary file for plotting.
Binary files will be rotated periodically.

```python plotter.py ./monitor_data/time_log_<index>.bin```
will then make nice interactive turbine delivery plots

To select specific slots from a larger log file:
```python grepper.py ./monitor_data/time_log_<index>.bin 1238412934 1238412938```

## Gossip abusers
```cargo xtask run  -- monitor log-gossip-invalid-senders```
will look for suspicious gossip packets and log them for you


## Reporting metrics / unattended mode

```SOLANA_METRICS_CONFIG="host=https://internal-metrics.solana.com:8086,db=<database>,u=<user>,p=<password>" cargo xtask run --  monitor bitrate --report-metrics gossip```
will report metrics into influxdb rather than showing GUI

## Working with doublezero

running with `--strip-gre` will attach to provided interface and strip GRE headers to get to the actual packets. So, on a doublezero host:
```cargo xtask run -- --strip-gre --interface=<actual_eth_ip> discover --gossip-addr <dz_ip_addr>:8001```
and then to actually run monitor:
```cargo xtask run -- --strip-gre --interface=<actual_eth_ip> monitor bitrate gossip```
