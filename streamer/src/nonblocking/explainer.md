# Overcommit Risk Management Formula

Three inputs feed into the risk score:

## 1. `adjusted_load` — how close to (or past) saturation

```
load_level = 1.0 - (bucket / burst_capacity)
adjusted_load = (load_level - 0.5) / (1.0 - 0.5)
```

Maps load into an activation-relative scale:
- load < 50% → negative → no action (early return)
- load = 50% → adjusted = 0.0
- load = 75% → adjusted = 0.5
- load = 100% (saturation) → adjusted = 1.0
- load = 150% (deep debt) → adjusted = 2.0

This is the "when to care" axis. Below activation, overcommit is irrelevant — system has headroom.

## 2. `overcommit_pressure` — how much of the budget is consumed

```
overcommit_pressure = aggregate_high_rtt_streams / max_overcommit
```

Sum of `last_applied_max_streams` for every connection with RTT > 50ms, divided by ceiling (1M). Simple fraction: 0 = no high-RTT streams allocated, 1.0 = at budget.

## 3. `rtt_factor` — this connection's individual risk contribution

```
rtt_factor = connection_rtt / high_rtt_threshold
```

- 50ms (threshold) → 1.0
- 100ms → 2.0
- 200ms → 4.0

Higher RTT = streams take longer to drain = more risk per stream.

## Combined risk score

```
risk_score = adjusted_load × overcommit_pressure × rtt_factor
```

Product of all three. All three must be non-trivial for risk to matter:
- Low load? Risk near zero regardless of overcommit.
- No overcommit? Risk zero regardless of load.
- Low RTT? This connection's risk is low even if aggregate is bad.

## Risk → reduction

```
if risk_score < 1.0:  no reduction
reduction = clamp(risk_score - 1.0,  0.0,  1.0)
effective_quota = base_quota × (1.0 - reduction)
floor = max(1, effective_quota)
```

- risk < 1.0 → full base quota
- risk = 1.5 → 50% reduction
- risk ≥ 2.0 → 100% reduction → floor (1 stream)

## Why this works for "higher RTT → withdrawn under lower load"

Consider two connections at same aggregate pressure (0.5):

| RTT | rtt_factor | risk at 75% load (adj=0.5) | risk at saturation (adj=1.0) |
|-----|-----------|---------------------------|------------------------------|
| 50ms | 1.0 | 0.5×0.5×1.0 = 0.25 → none | 1.0×0.5×1.0 = 0.5 → none |
| 100ms | 2.0 | 0.5×0.5×2.0 = 0.5 → none | 1.0×0.5×2.0 = 1.0 → threshold |
| 200ms | 4.0 | 0.5×0.5×4.0 = 1.0 → threshold | 1.0×0.5×4.0 = 2.0 → full reduction |

200ms connection starts getting throttled at 75% load. 100ms connection doesn't get throttled until saturation. 50ms connection (at threshold) never gets throttled at this pressure level. That's the desired behavior — higher RTT peers feel the squeeze earlier.
