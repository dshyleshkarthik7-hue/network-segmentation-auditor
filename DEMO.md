# Demo procedure

## 1. Safe design (expect exit 0)

```bash
network-segmentation-auditor -c examples/safe-web-tier.json --exit-code --mermaid
echo $?   # → 0
```

Classic Internet → DMZ → App → Data is reported as INFO only (expected tiering).

## 2. Direct public database (expect HIGH + exit 2)

```bash
network-segmentation-auditor -c examples/unsafe-public-db.json --exit-code
echo $?   # → 2
```

## 3. Unexpected transitive exposure — the key v2.0 demo (expect HIGH + exit 2)

Internet reaches DATA via APPLICATION with **no public/DMZ entry point**:

```
INTERNET → APPLICATION → DATA
```

```bash
network-segmentation-auditor -c examples/transitive-exposure.json --exit-code
echo $?   # → 2
```

Look for the finding:

```
TRANSITIVE_SENSITIVE_REACHABILITY: Internet-originated traffic can reach
sensitive zone DATA via unexpected 2-hop path: INTERNET → APPLICATION → DATA
(first hop is not a public/DMZ zone).
```

## 4. Overlapping CIDRs (expect MEDIUM)

```bash
network-segmentation-auditor -c examples/overlapping-cidrs.json --exit-code
```
