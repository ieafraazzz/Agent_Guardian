# Phase 6: research evaluation

## Reproducing the evaluation

Install dependencies and Chromium, then run:

```text
npm install
npx playwright install chromium
npm run evaluate
```

The command rebuilds the project, replays the frozen corpus across 14 configurations, runs three live Chromium malicious/benign twins, checks the full configuration against every expected decision, and writes:

- `evaluation/results/latest/evaluation.json` — complete per-scenario evidence and metrics;
- `evaluation/results/latest/results.csv` — analysis-friendly long-form results;
- `evaluation/results/latest/summary.md` — overall and held-out ablation tables;
- `evaluation/results/latest/live-subset.json` — repeated browser side-effect results.

Use `--repetitions N` for repeated deterministic replays and `--live-repetitions N` for additional live Chromium runs:

```text
node dist/evaluate-cli.js --repetitions 5 --live-repetitions 5
```

## Frozen protocol

The committed inputs are:

- `evaluation/frozen-policy-v1.json` — rule decisions and metric definitions;
- `evaluation/corpus.jsonl` — 25 labelled cases with immutable IDs, development/held-out splits, tags, source statements, expected decisions, attack goals, and partial-influence labels.

The runner records SHA-256 hashes of both files in every result. Changing either input therefore creates a visibly different evaluation run.

The corpus covers metadata poisoning, Unicode obfuscation, malicious arguments and results, rug pulls, nested schema changes, shadowing, credential and financial flows, delayed behavior chains, intent violations, browser hidden text, phishing, downloads, cross-surface email and execution, user override, and benign controls.

## Configurations and metrics

The runner evaluates:

- no Guardian;
- each of integrity, semantic, behavior, intent, and provenance alone;
- full Guardian;
- full Guardian minus each layer;
- MCP-only and browser-only lanes.

Reported values include attack success, precision, recall, F1, false positives and negatives, benign completion, permission frequency, simulated overrides, partial attacker influence, detector latency, memory delta, overall results, and held-out results. Proportions include 95% Wilson score intervals.

An attack is counted as detected when its policy outcome is `ASK` or `BLOCK`. It succeeds when it receives `ALLOW`, or when a corpus case explicitly models the user overriding an `ASK`. Consequently, the full-system attack-success rate is intentionally non-zero: the override scenario remains visible instead of being reclassified as a defense success.

## Current measured result

For the committed 25-case corpus, the full configuration matched every frozen expected decision, achieved 100% precision and recall, and retained 100% benign completion. Its 5.3% attack-success rate is the single explicit user-override case. The no-Guardian configuration allowed all malicious cases. Removing any one of the five layers reduced both overall and held-out recall, with provenance producing the largest reduction in this corpus.

The three-run live Chromium subset held all three poisoned form submissions before the HTTP side effect and allowed all three benign twins to submit successfully.

## Limitations and claim boundary

- The corpus is deliberately small and synthetic; it verifies the prototype and ablation logic but does not establish population-level generalization.
- “Benchmark-inspired” held-out cases are newly written scenarios based on attack families described in the literature. No third-party benchmark items are copied, and no claim of benchmark comparability is made.
- The repeated live subset exercises real Chromium and enforcement side effects, but it is not a stochastic hosted-LLM study. No model API key or paid external service is required.
- The semantic-layer measurements use the deterministic local normalization and injection rules. The optional Gemini sandbox is excluded so the run remains offline and reproducible; it must be evaluated separately before making claims about model-assisted detection.
- Detector latency excludes hosted-model and network latency. Memory deltas are process-level approximations and may be noisy.
- Confidence intervals quantify sampling uncertainty for this corpus; they do not correct corpus-selection bias.
- A larger external corpus, multiple live agent models, and independently authored benign workloads remain appropriate future validation work.
