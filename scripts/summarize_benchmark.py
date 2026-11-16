#!/usr/bin/env python3

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# Returns the supported SHA implementation identifier and display label.
def implementation(statement):
    value = statement["sha_implementation"]
    if value not in ("NotUsed", "OfficialPeriodic"):
        raise ValueError(f"Unsupported SHA implementation: {value!r}")
    return value, value

# Computes summary statistics for the measured samples.
def stats(values):

    if any(value is None for value in values):
        return None
    return dict(mean=statistics.mean(values), median=statistics.median(values),
                minimum=min(values), maximum=max(values),
                sample_stdev=statistics.stdev(values) if len(values) > 1 else None)

# Returns the recorded mean for the selected metric.
def mean(entry, key):
    value = entry.get(key)
    return value["mean"] if value is not None else None

# Formats a metric using the requested unit scale and precision.
def fmt(value, scale=1, places=4):
    return "n/a" if value is None else f"{value * scale:.{places}f}"

# Sums the selected phase across proof components.
def phase_total(entries, key):
    values = [mean(entry, key) for entry in entries]
    return None if any(value is None for value in values) else sum(values)

# Renders saved per-component measurements without changing provenance.
def render_summary(result):

    components = []
    for saved in result["components"]:

        entry = dict(saved)
        entry.setdefault("sha_implementation_label", implementation(entry)[1])
        entry.setdefault("proof_verification_seconds", entry.get("verifier_online_seconds"))
        entry.setdefault("prover_preprocessing_seconds", entry.get("public_preprocessing_seconds"))
        if "prover_with_public_preprocessing_seconds" not in entry:
            prover, preprocessing = mean(entry, "prover_seconds"), mean(entry, "prover_preprocessing_seconds")
            entry["prover_with_public_preprocessing_seconds"] = (
                dict(mean=prover + preprocessing) if prover is not None and preprocessing is not None else None)
        components.append(entry)
    lines = [
        "# Verifiable CKKS MPC benchmark", "",
        f"Scope: {result['scope']}; N={result['params']['n']}; "
        f"{result['repetitions']} measured repetitions after {result['warmups']} warmup(s) per statement.", "",
        "Values are means. Each row reports one KG, Enc or Dec proof component separately, averaged over the recorded samples.",
        "All phase times are seconds except the explicitly labeled proof-verification column in milliseconds.",
        "Proof sizes are bytes (1 MiB = 1,048,576 bytes). n/a denotes a phase not measured separately in an older run.", "",
        "| Variant | SHA implementation | Layout | Component | Samples | Prover s | Prover preprocessing s | Prover total s | Proof bytes |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in components:
        lines.append(
            f"| {entry['variant']} | {entry['sha_implementation_label']} | {entry['layout']} | "
            f"{entry['algorithm']} | {entry['samples']} | {fmt(mean(entry, 'prover_seconds'))} | "
            f"{fmt(mean(entry, 'prover_preprocessing_seconds'))} | "
            f"{fmt(mean(entry, 'prover_with_public_preprocessing_seconds'))} | "
            f"{fmt(mean(entry, 'proof_size_bytes'), places=0)} |")
    lines += [
        "", "FRI profile: " + json.dumps(result.get("fri_profile"), sort_keys=True)
        + "; compact public openings: " + str(result.get("compact_public_openings", False)), "",
        "| Variant | Layout | Component | Wire proof KiB | Expanded proof KiB | Public opening saved KiB | Proven RBR bits | LDR non-hash bits |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in components:
        sec = entry["security"]
        lines.append(
            f"| {entry['variant']} | {entry['layout']} | {entry['algorithm']} | "
            f"{fmt(mean(entry, 'proof_size_bytes'), scale=1/1024, places=1)} | "
            f"{fmt(mean(entry, 'expanded_proof_size_bytes'), scale=1/1024, places=1)} | "
            f"{fmt(mean(entry, 'public_opening_saved_bytes'), scale=1/1024, places=1)} | "
            f"{sec['proven_rbr_bits']:.1f} | {fmt(sec.get('ldr_non_hash_bits'), places=2)} |")
    lines += [
        "",
        "| Variant | SHA implementation | Layout | Component | Public frontend s | Public preprocessing s | Metadata prep ms (included) | Public setup total s | Proof verification ms | Verifier total s |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in components:
        lines.append(
            f"| {entry['variant']} | {entry['sha_implementation_label']} | {entry['layout']} | "
            f"{entry['algorithm']} | {fmt(mean(entry, 'verifier_frontend_seconds'))} | "
            f"{fmt(mean(entry, 'verifier_preprocessing_seconds'))} | "
            f"{fmt(mean(entry, 'verifier_metadata_preprocessing_seconds'), scale=1000, places=3)} | "
            f"{fmt(mean(entry, 'verifier_public_setup_seconds'))} | "
            f"{fmt(mean(entry, 'proof_verification_seconds'), scale=1000, places=3)} | "
            f"{fmt(mean(entry, 'verifier_cold_seconds'))} |")
    comparisons = result.get("comparisons", [])
    if comparisons:
        lines += [
            "", "| Ablation | Component | Prover / baseline | Proof verification / baseline | Verifier total / baseline | Size / baseline |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
        for entry in comparisons:
            ratios = entry["ratios"]
            lines.append(
                f"| {entry['layout']} | {entry['variant']}/{entry['algorithm']} | "
                f"{fmt(ratios.get('prover_seconds'), places=3)} | "
                f"{fmt(ratios.get('proof_verification_seconds', ratios.get('verifier_online_seconds')), places=3)} | "
                f"{fmt(ratios.get('verifier_cold_seconds'), places=3)} | "
                f"{fmt(ratios.get('proof_size_bytes'), places=3)} |")
    lines += [
        "",
        "Prover = witness/circuit/trace construction + proof core + serialization. Prover preprocessing is separate; prover total includes it.",
        "Public frontend constructs the expected circuit, computes public NTTs and allocates zero-placeholder traces. Public preprocessing constructs its authenticated commitment and backend setup data.",
        "Proof verification = envelope decode + compact public opening reconstruction + proof shape checks + cryptographic verification, with prepared public data.",
        "Verifier total = public frontend + public preprocessing + proof verification. Public setup total is the sum of the first two phases.",
        "Proof-file I/O, workflow consistency checks and statement-digest calculation are outside these phase timers.",
        "Setup is measured once per distinct full statement and added to every corresponding total without amortization across proof repetitions.",
        "Cached prepared data is valid for the identical full public statement, backend profile and FRI profile. New ciphertexts, shares or sessions normally require new setup.",
        "Fixture/sampler generation is shared across variants and recorded separately. Masks are fresh for every proof, including repetitions.",
        "Security values are upstream proven round-by-round estimates including LogUp; full FS/session security and PK short-opening binding retain the documented assumptions.",
        "",
    ]
    return "\n".join(lines)

# Writes the human-readable benchmark summary.
def write_markdown(directory, result):
    markdown = render_summary(result)
    (directory / "summary.md").write_text(markdown)
    print(markdown)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", nargs="?", help="verified benchmark directory to summarize")
parser.add_argument("--render-only", metavar="DIR",
                    help="render existing summary.json; write only summary.md and preserve measured provenance")
args = parser.parse_args()
if (args.directory is None) == (args.render_only is None):
    parser.error("provide either DIRECTORY or --render-only DIR")
if args.render_only is not None:
    directory = Path(args.render_only).resolve()
    write_markdown(directory, json.loads((directory / "summary.json").read_text()))
    sys.exit(0)

root = Path(__file__).resolve().parents[1]
directory = Path(args.directory).resolve()
run = json.loads((directory / "run.json").read_text())
assert run["metadata"].get("independent_verifier_completed"), "Run the independent verifier first"
groups = defaultdict(list)
implementations = {}
for record in run["records"]:
    statement, metrics = record["statement"], dict(record["metrics"])
    assert metrics["independent_process_verified"] and metrics["verified"]
    assert metrics["security"]["proven_rbr_bits"] >= 128
    if "ldr_non_hash_bits" in metrics["security"]:
        assert metrics["security"]["ldr_non_hash_bits"] >= 144
    metrics.setdefault("proof_verification_seconds", metrics.get("verifier_online_seconds"))
    metrics.setdefault("prover_preprocessing_seconds", metrics.get("public_preprocessing_seconds"))
    if "prover_with_public_preprocessing_seconds" not in metrics:
        preprocessing = metrics["prover_preprocessing_seconds"]
        metrics["prover_with_public_preprocessing_seconds"] = (
            metrics["prover_seconds"] + preprocessing if preprocessing is not None else None)
    raw_implementation, label = implementation(statement)
    key = (statement["variant"], label, statement["layout"], statement["algorithm"])
    groups[key].append(metrics)
    implementations[key] = raw_implementation

columns = [
    "prover_seconds", "prover_core_seconds", "witness_trace_seconds",
    "prover_preprocessing_seconds", "public_preprocessing_seconds",
    "prover_with_public_preprocessing_seconds", "proof_serialization_seconds",
    "verifier_frontend_seconds", "verifier_preprocessing_seconds",
    "prover_metadata_preprocessing_seconds", "verifier_metadata_preprocessing_seconds",
    "verifier_public_setup_seconds", "proof_verification_seconds",
    "verifier_online_seconds", "verifier_cold_seconds", "proof_size_bytes",
    "expanded_proof_size_bytes", "public_opening_saved_bytes",
]
summary = []
for (variant, implementation_label, layout, algorithm), records in groups.items():
    key = (variant, implementation_label, layout, algorithm)
    entry = dict(variant=variant, sha_implementation=implementations[key],
                 sha_implementation_label=implementation_label,
                 layout=layout, algorithm=algorithm, samples=len(records))
    for name in columns:
        entry[name] = stats([record.get(name) for record in records])
    entry["security"] = records[0]["security"]
    entry["private_ntts"] = records[0]["private_ntts"]
    entry["sha_compressions"] = records[0]["sha_compressions"]
    entry["native_sha_rows"] = records[0].get("native_sha_rows")
    if entry["native_sha_rows"] is None and isinstance(entry["sha_implementation"], dict):
        entry["native_sha_rows"] = entry["sha_implementation"].get("Official", {}).get("rows")
    summary.append(entry)

sources = [*sorted((root / "crates/mpc/src").rglob("*.rs")), root / "Cargo.lock",
           root / "crates/mpc/Cargo.toml", root / "dependencies/plonky3-revision.txt",
           *sorted((root / "crates/mpc/src/sha_frozen").glob("*.bin"))]
binary_name = run["metadata"].get("benchmark_binary_name") or "vmpckks"
binary_hash = run["metadata"].get("benchmark_binary_sha256")
if binary_hash is None:
    binary_hash = hashlib.sha256((root / "target/probe/release" / binary_name).read_bytes()).hexdigest()
provenance = {
    "capture_stage": "report generation; source/binary hashes are a checkout snapshot, not a build attestation",
    "platform": platform.platform(),
    "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
    "cpu": next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")),
    "rayon_threads": run["metadata"]["rayon_threads"],
    "source_sha256": {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
    "run_sha256": hashlib.sha256((directory / "run.json").read_bytes()).hexdigest(),
    "binary_name": binary_name,
    "binary_sha256": binary_hash,
    "build": run["metadata"].get("build"),
    "prover_options": run["metadata"].get("prover_options"),
    "verifier_cache": run["metadata"].get("verifier_cache"),
    "public_data_patch_sha256": hashlib.sha256((root / "dependencies/plonky3-public-data.patch").read_bytes()).hexdigest(),
    "parallel_salt_patch_sha256": hashlib.sha256((root / "dependencies/plonky3-parallel-salts.patch").read_bytes()).hexdigest(),
    "periodic_batch_patch_sha256": hashlib.sha256((root / "dependencies/plonky3-periodic-batch.patch").read_bytes()).hexdigest(),
    "verifier_cache_patch_sha256": hashlib.sha256((root / "dependencies/plonky3-verifier-cache.patch").read_bytes()).hexdigest(),
}
result = dict(scope=run["scope"], params=run["params"], repetitions=run["repetitions"],
              warmups=run["warmups"], metadata=run["metadata"], provenance=provenance,
              components=summary)
result["fri_profile"] = run.get("fri_profile")
result["compact_public_openings"] = run.get("compact_public_openings", False)

if run["scope"] == "two-party-workflow":

    decoded_outputs = []
    for variant, layout in sorted({(record["statement"]["variant"], record["statement"]["layout"])
                                   for record in run["records"]}):
        shares = {record["statement"]["party"]: record["statement"] for record in run["records"]
                  if record["statement"]["variant"] == variant and record["statement"]["layout"] == layout
                  and record["statement"]["algorithm"] == "Dec"}
        q, kappa = 18446744069414584321, run["params"]["kappa"]
        combined = [(c + x + y) % q for c, x, y in zip(shares[0]["c0"], shares[0]["d"], shares[1]["d"])]
        digits = [((value + kappa // 2) // kappa) % 8 for value in combined]
        decoded_outputs.append(dict(variant=variant, layout=layout,
                                    sha_implementation=implementation(shares[0])[0], digits=digits,
                                    decoded_sha256=hashlib.sha256(bytes(digits)).hexdigest()))
    assert len({output["decoded_sha256"] for output in decoded_outputs}) == 1, "Variants disagree on the public output"
    (directory / "decoded.json").write_text(json.dumps(decoded_outputs, indent=2) + "\n")
    result["combined_decoded_sha256"] = decoded_outputs[0]["decoded_sha256"]
    totals = []
    by_variant = defaultdict(list)
    for entry in summary:
        by_variant[(entry["variant"], entry["layout"])].append(entry)
    for (variant, layout), entries in by_variant.items():
        assert len(entries) == 3 and {entry["algorithm"] for entry in entries} == {"Keygen", "Enc", "Dec"}
        active_implementations = {entry["sha_implementation_label"] for entry in entries
                                  if entry["sha_implementation_label"] != "NotUsed"}
        assert len(active_implementations) <= 1, "Split SHA implementations into separate full-workflow runs"
        label = next(iter(active_implementations), "NotUsed")
        names = [
            "prover_seconds", "prover_preprocessing_seconds", "public_preprocessing_seconds",
            "prover_with_public_preprocessing_seconds", "verifier_frontend_seconds",
            "verifier_preprocessing_seconds", "verifier_public_setup_seconds",
            "proof_verification_seconds", "verifier_online_seconds",
            "verifier_cold_seconds", "proof_size_bytes",
        ]
        total = {name: phase_total(entries, name) for name in names}
        totals.append(dict(variant=variant, layout=layout, sha_implementation=label, per_party=total,
                           two_party={name: 2 * value if value is not None else None
                                      for name, value in total.items()}))
    result["totals"] = totals
(directory / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
write_markdown(directory, result)
