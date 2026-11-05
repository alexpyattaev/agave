#!/usr/bin/python
"""Analytical Rotor egress model with a saturating stake->relay-weight
compression, so no single node is asked to egress more than a bandwidth cap.

Rotor: each shred has one relayer, chosen with probability = the node's
*effective* relay weight w(s). The relayer fans the shred out to the whole
cluster (~N peers). So a node's sustained relay egress is

    egress(w) = w * shreds_per_second * N * packet_bits   [bits/s]

With the plain stake-proportional model w(s)=s this is linear in stake and
explodes for high-stake nodes. We replace s with a compressed weight w(s)
that saturates above a knee, bounding egress at CAP_GBPS.

NOTE on reproducibility: relay assignment is consensus-relevant, so the
compression must be bit-exact across validators. tanh() is float and not
portable; a *truncated Taylor series* of tanh does NOT work (it only
approximates tanh for |x|<~1, i.e. the un-saturated regime, and diverges
past the knee -- demonstrated below). Use the integer-exact clamp or the
rational "parallel" knee instead.
"""

# ---- cluster / traffic parameters -------------------------------------------
SHREDS_PER_SECOND = 512 * 5 * 64  # 512 FEC sets/slot, 5 slots/s, 64 shreds/FEC
N = 6000                          # nodes in the cluster
PKT_BITS = 1300 * 8               # 1300 bytes/shred on the wire
CAP_GBPS = 50.0                   # target: no node asked to egress more than this

# Per-unit-weight egress: a node relaying fraction f of all shreds egresses
#   f * GBPS_PER_UNIT_WEIGHT  Gbps.
GBPS_PER_UNIT_WEIGHT = SHREDS_PER_SECOND * N * PKT_BITS / 1e9

# Effective relay-weight at which egress == CAP_GBPS. This is the saturation
# value the compression must converge to.
F_CAP = CAP_GBPS / GBPS_PER_UNIT_WEIGHT

print(f"GBPS_PER_UNIT_WEIGHT = {GBPS_PER_UNIT_WEIGHT:,.1f} Gbps   (= egress at w=1)")
print(f"F_CAP (weight giving {CAP_GBPS} Gbps) = {F_CAP*100:.4f}% of relay share")
print(f"=> saturation knee sits at stake ~ {F_CAP*100:.3f}%, NOT 1%: at N={N} and")
print(f"   full fanout, a {F_CAP*100:.3f}% relay share already hits {CAP_GBPS} Gbps.\n")

# Use s_cap = F_CAP so the compressed weight saturates exactly at the cap.
S_CAP = F_CAP


def egress_gbps(w: float) -> float:
    return w * GBPS_PER_UNIT_WEIGHT


# ---- compression functions w(s) ---------------------------------------------
def w_linear(s):            # current model: strictly stake-proportional
    return s


def w_clamp(s):             # exact, integer-min; hard guarantee w <= S_CAP
    return min(s, S_CAP)


def w_rational(s):          # smooth "tanh-style" knee, integer-divide friendly
    # s_cap * x/(1+x) with x=s/s_cap  ==  s*s_cap/(s+s_cap)
    return s * S_CAP / (s + S_CAP)


def w_tanh(s):              # reference only -- float, NOT reproducible
    import math
    return S_CAP * math.tanh(s / S_CAP)


def w_taylor(s, terms):     # REQUESTED, but broken past the knee (see output)
    x = s / S_CAP
    phi = x
    if terms >= 2:
        phi -= x**3 / 3
    if terms >= 3:
        phi += 2 * x**5 / 15
    return S_CAP * phi


# ---- fixed-point (integer) version of the rational knee ---------------------
# Proves the rational knee is bit-exact: stake and S_CAP in parts-per-billion.
PPB = 1_000_000_000


def w_rational_fixed_ppb(s_ppb: int) -> int:
    cap = int(round(S_CAP * PPB))
    # s*cap/(s+cap) in integers; round-to-nearest.
    num = s_ppb * cap
    den = s_ppb + cap
    return (num + den // 2) // den


# ---- sweep ------------------------------------------------------------------
stakes = [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.02, 0.04, 0.10]
hdr = f"{'stake':>7} | {'linear':>12} {'clamp':>10} {'rational':>10} {'tanh(ref)':>10} {'taylor2':>10} {'taylor3':>10}"
print(hdr)
print("-" * len(hdr))
for s in stakes:
    row = (
        f"{s*100:6.3f}% | "
        f"{egress_gbps(w_linear(s)):11.1f}  "
        f"{egress_gbps(w_clamp(s)):9.1f}  "
        f"{egress_gbps(w_rational(s)):9.1f}  "
        f"{egress_gbps(w_tanh(s)):9.1f}  "
        f"{egress_gbps(w_taylor(s,2)):9.1f}  "
        f"{egress_gbps(w_taylor(s,3)):9.1f}"
    )
    print(row)

print("\n(values are Gbps of relay egress demanded of one node at that stake)")
print("Watch the taylor2/taylor3 columns go negative/explode past ~0.5% stake:")
print("truncated tanh-Taylor cannot cap. clamp and rational stay <= 50 Gbps.\n")

# fixed-point determinism check for the recommended rational knee
print("fixed-point (ppb) rational knee matches float within rounding:")
for s in stakes:
    f = egress_gbps(w_rational(s))
    i = egress_gbps(w_rational_fixed_ppb(int(round(s * PPB))) / PPB)
    print(f"  stake {s*100:6.3f}%:  float={f:7.2f} Gbps   fixed={i:7.2f} Gbps   diff={abs(f-i):.4g}")

# ---- caveat: renormalization can break the cap ------------------------------
print(
    "\nCAVEAT: each shred needs exactly one relayer, so relay probability is\n"
    "w(s_i)/sum_j w(s_j). Compressing whales lowers the denominator, scaling\n"
    "everyone (incl. capped nodes) UP by 1/sum(w). If whales hold a large stake\n"
    "share, capped nodes can exceed CAP after renorm. To *guarantee* the cap,\n"
    "clamp the final per-node egress (or iterate clamp+renormalize), don't just\n"
    "clamp the pre-normalized weight."
)
