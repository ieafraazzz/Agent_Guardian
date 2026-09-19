# Agent Guardian evaluation

Generated: 2026-09-19T05:33:57.419Z
Corpus SHA-256: `1e03bdf2dc5ca0fc956621749deab8cae266f0c2c25bdd0dba234d88edfa0820`
Policy SHA-256: `723fecded4c2040899ff2dd4944ed60f7ee8e3a59bc27f58fa507dab38154331`
Repetitions: 1

| Configuration | ASR | Precision | Recall | F1 | Benign completion | Permission rate | p95 latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| No Guardian | 100.0% | 0.0% | 0.0% | 0.000 | 100.0% | 0.0% | 0.081 |
| Integrity only | 84.2% | 100.0% | 15.8% | 0.273 | 100.0% | 4.0% | 0.123 |
| Semantic only | 78.9% | 100.0% | 26.3% | 0.417 | 100.0% | 16.0% | 2.741 |
| Behavior only | 89.5% | 100.0% | 10.5% | 0.190 | 100.0% | 4.0% | 0.022 |
| Intent only | 89.5% | 100.0% | 10.5% | 0.190 | 100.0% | 8.0% | 3.410 |
| Provenance only | 63.2% | 100.0% | 36.8% | 0.538 | 100.0% | 16.0% | 3.932 |
| Full Guardian | 5.3% | 100.0% | 100.0% | 1.000 | 100.0% | 48.0% | 4.980 |
| Full minus Integrity | 21.1% | 100.0% | 84.2% | 0.914 | 100.0% | 44.0% | 5.014 |
| Full minus Semantic | 26.3% | 100.0% | 73.7% | 0.848 | 100.0% | 32.0% | 6.441 |
| Full minus Behavior | 15.8% | 100.0% | 89.5% | 0.944 | 100.0% | 44.0% | 6.212 |
| Full minus Intent | 15.8% | 100.0% | 89.5% | 0.944 | 100.0% | 40.0% | 6.995 |
| Full minus Provenance | 42.1% | 100.0% | 63.2% | 0.774 | 100.0% | 32.0% | 7.605 |
| MCP lane only | 31.6% | 100.0% | 73.7% | 0.848 | 100.0% | 36.0% | 0.039 |
| Browser lane only | 84.2% | 100.0% | 15.8% | 0.273 | 100.0% | 8.0% | 7.787 |

## Held-out split

| Configuration | Held-out ASR | Held-out precision | Held-out recall | Held-out F1 |
|---|---:|---:|---:|---:|
| No Guardian | 100.0% | 0.0% | 0.0% | 0.000 |
| Integrity only | 90.0% | 100.0% | 10.0% | 0.182 |
| Semantic only | 80.0% | 100.0% | 30.0% | 0.462 |
| Behavior only | 90.0% | 100.0% | 10.0% | 0.182 |
| Intent only | 90.0% | 100.0% | 10.0% | 0.182 |
| Provenance only | 60.0% | 100.0% | 40.0% | 0.571 |
| Full Guardian | 10.0% | 100.0% | 100.0% | 1.000 |
| Full minus Integrity | 20.0% | 100.0% | 90.0% | 0.947 |
| Full minus Semantic | 30.0% | 100.0% | 70.0% | 0.824 |
| Full minus Behavior | 20.0% | 100.0% | 90.0% | 0.947 |
| Full minus Intent | 20.0% | 100.0% | 90.0% | 0.947 |
| Full minus Provenance | 50.0% | 100.0% | 60.0% | 0.750 |
| MCP lane only | 40.0% | 100.0% | 70.0% | 0.824 |
| Browser lane only | 80.0% | 100.0% | 20.0% | 0.333 |

Intervals in `evaluation.json` are 95% Wilson score intervals. Latency and memory values are measurements of deterministic detector replay, not hosted-model latency.
