"""Lightweight, explainable quality analysis for WAF payload CSV datasets."""

import csv
import io
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median
from urllib.parse import unquote_plus


PAYLOAD_COLUMNS = ("payload", "payloads", "request", "text", "input", "query")
LABEL_COLUMNS = ("status code", "status_code", "status", "label", "class", "target")
CATEGORY_COLUMNS = ("attack category", "attack_category", "attack type", "attack_type", "category", "family")
CHUNK_SIZE = 256


def _column(fieldnames, candidates):
    lookup = {(name or "").strip().lower(): name for name in fieldnames or []}
    return next((lookup[name] for name in candidates if name in lookup), None)


def _read_text(input_path):
    """Read common dataset encodings without changing the source file."""
    raw = Path(input_path).read_bytes()
    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("dataset", raw, 0, len(raw), "unsupported encoding")


def _canonical(payload):
    try:
        payload = unquote_plus(payload)
    except (UnicodeDecodeError, ValueError):
        pass
    return re.sub(r"\s+", " ", payload.strip().lower())


def _entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _normalized_entropy(counts):
    nonzero = [count for count in counts.values() if count]
    if len(nonzero) < 2:
        return 0.0
    total = sum(nonzero)
    return -sum((count / total) * math.log2(count / total) for count in nonzero) / math.log2(len(nonzero))


def _percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]


def _metric(name, value, score, weight, status, explanation):
    return {
        "name": name, "value": value, "score": round(score, 2), "weight": weight,
        "status": status, "explanation": explanation,
    }


def analyze_dataset(input_path, output_dir):
    """Analyze *input_path*, persist JSON/CSV reports, and return the report."""
    input_path, output_dir = Path(input_path), Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_data = input_path.read_bytes()
    file_entropy = _entropy(raw_data)
    chunk_entropies = [
        _entropy(raw_data[offset:offset + CHUNK_SIZE])
        for offset in range(0, len(raw_data), CHUNK_SIZE)
    ]
    chunk_entropy_mean = mean(chunk_entropies) if chunk_entropies else 0.0

    reader = csv.DictReader(io.StringIO(_read_text(input_path), newline=""))
    payload_column = _column(reader.fieldnames, PAYLOAD_COLUMNS)
    label_column = _column(reader.fieldnames, LABEL_COLUMNS)
    category_column = _column(reader.fieldnames, CATEGORY_COLUMNS)
    if not payload_column or not label_column:
        raise ValueError(
            "Dataset must contain a payload column and a label/status column. "
            f"Found: {reader.fieldnames or []}"
        )
    rows = list(reader)

    total = len(rows)
    valid = []
    missing_payloads = missing_labels = 0
    for row in rows:
        payload = (row.get(payload_column) or "").strip()
        label = (row.get(label_column) or "").strip()
        missing_payloads += not bool(payload)
        missing_labels += not bool(label)
        if payload and label:
            valid.append((payload, label))

    payloads = [item[0] for item in valid]
    labels = Counter(item[1] for item in valid)
    categories = Counter(
        (row.get(category_column) or "").strip()
        for row in rows
        if category_column and (row.get(category_column) or "").strip()
    )
    canonical_pairs = [(_canonical(payload), label) for payload, label in valid]
    canonical_counts = Counter(payload for payload, _ in canonical_pairs)
    unique_exact = len(set(payloads))
    unique_canonical = len(canonical_counts)
    validity_rate = len(valid) / total if total else 0.0
    exact_unique_rate = unique_exact / len(valid) if valid else 0.0
    canonical_unique_rate = unique_canonical / len(valid) if valid else 0.0

    labels_by_payload = defaultdict(set)
    for payload, label in canonical_pairs:
        labels_by_payload[payload].add(label)
    conflicts = sum(1 for values in labels_by_payload.values() if len(values) > 1)
    conflict_rate = conflicts / unique_canonical if unique_canonical else 0.0

    entropies = [_entropy(payload) for payload in payloads]
    lengths = [len(payload) for payload in payloads]
    label_entropy = _normalized_entropy(labels)
    largest_class_share = max(labels.values(), default=0) / len(valid) if valid else 1.0

    integrity_score = 100 * validity_rate * max(0.0, 1 - (10 * conflict_rate))
    redundancy_score = 100 * canonical_unique_rate
    balance_score = 100 * label_entropy
    # Character entropy is descriptive, not "more is always better". Diversity scoring
    # therefore combines uniqueness with vocabulary richness instead of rewarding noise.
    characters = set("".join(payloads))
    character_richness = min(len(characters) / 64, 1.0)
    diversity_score = 100 * ((0.75 * canonical_unique_rate) + (0.25 * character_richness))

    metrics = [
        _metric("Integrity", round(validity_rate, 4), integrity_score, 30,
                "good" if integrity_score >= 80 else "warning" if integrity_score >= 60 else "poor",
                "Valid rows, penalized strongly for identical payloads with conflicting labels."),
        _metric("Payload diversity", round(canonical_unique_rate, 4), diversity_score, 30,
                "good" if diversity_score >= 80 else "warning" if diversity_score >= 60 else "poor",
                "Canonical uniqueness plus character-vocabulary richness."),
        _metric("Low redundancy", round(canonical_unique_rate, 4), redundancy_score, 20,
                "good" if redundancy_score >= 80 else "warning" if redundancy_score >= 60 else "poor",
                "Percentage remaining unique after decoding, case, and whitespace normalization."),
        _metric("Label balance", round(label_entropy, 4), balance_score, 20,
                "good" if balance_score >= 80 else "warning" if balance_score >= 60 else "poor",
                "Normalized Shannon entropy of the observed labels; 1.0 is evenly balanced."),
    ]
    score = sum(item["score"] * item["weight"] for item in metrics) / 100
    critical = []
    if total == 0:
        critical.append("The dataset contains no records.")
    if conflict_rate > 0.01:
        critical.append("More than 1% of canonical payloads have conflicting labels.")
    if len(valid) < 100:
        critical.append("Fewer than 100 valid records are available.")
    if critical:
        score = min(score, 39)
    verdict = "Suitable" if score >= 80 else "Usable with caution" if score >= 60 else "High risk" if score >= 40 else "Unsuitable"

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_file": input_path.name,
        "verdict": verdict,
        "score": round(score, 2),
        "score_scale": {"Suitable": "80-100", "Usable with caution": "60-79.99", "High risk": "40-59.99", "Unsuitable": "0-39.99"},
        "summary": {
            "total_rows": total, "valid_rows": len(valid), "missing_payloads": missing_payloads,
            "missing_labels": missing_labels, "unique_exact_payloads": unique_exact,
            "unique_canonical_payloads": unique_canonical, "exact_duplicate_rows": len(valid) - unique_exact,
            "canonical_duplicate_rows": len(valid) - unique_canonical,
            "conflicting_canonical_payloads": conflicts, "conflict_rate": round(conflict_rate, 6),
            "labels": dict(sorted(labels.items())), "largest_class_share": round(largest_class_share, 4),
        },
        "payload_statistics": {
            "length_mean": round(mean(lengths), 2) if lengths else 0, "length_median": median(lengths) if lengths else 0,
            "length_p10": _percentile(lengths, .10), "length_p90": _percentile(lengths, .90),
            "character_entropy_mean_bits": round(mean(entropies), 4) if entropies else 0,
            "character_entropy_median_bits": round(median(entropies), 4) if entropies else 0,
            "distinct_characters": len(characters),
        },
        "file_entropy": {
            "file_size_bytes": len(raw_data), "chunk_size_bytes": CHUNK_SIZE,
            "whole_file_bits_per_byte": round(file_entropy, 4),
            "chunk_count": len(chunk_entropies),
            "chunk_mean_bits_per_byte": round(chunk_entropy_mean, 4),
            "chunk_min_bits_per_byte": round(min(chunk_entropies), 4) if chunk_entropies else 0,
            "chunk_max_bits_per_byte": round(max(chunk_entropies), 4) if chunk_entropies else 0,
            "chunk_stddev_bits_per_byte": round(
                math.sqrt(mean([(value - chunk_entropy_mean) ** 2 for value in chunk_entropies])), 4
            ) if chunk_entropies else 0,
            "interpretation": "Diagnostic only: CSV formatting, encoding, row order, and repeated labels affect byte entropy.",
        },
        "attack_category_coverage": {
            "available": bool(category_column), "column": category_column,
            "distinct_categories": len(categories), "counts": dict(sorted(categories.items())),
            "interpretation": "Coverage can only be assessed when the dataset supplies an attack/category column.",
        },
        "metrics": metrics,
        "critical_findings": critical,
        "limitations": [
            "This is an internal quality heuristic, not proof that the dataset represents production traffic.",
            "Train/test leakage cannot be measured without split membership or separate datasets.",
            "Attack-family coverage cannot be measured without an attack/category column.",
            "Thresholds are transparent defaults and should be calibrated for the research domain.",
        ],
    }

    with (output_dir / "dataset_analysis.json").open("w", encoding="utf-8") as target:
        json.dump(report, target, indent=2, ensure_ascii=False)
    with (output_dir / "dataset_analysis.csv").open("w", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow(["metric", "value", "score", "weight", "status", "explanation"])
        for item in metrics:
            writer.writerow([item[key] for key in ("name", "value", "score", "weight", "status", "explanation")])
        writer.writerow(["Overall verdict", verdict, report["score"], 100, verdict, "See JSON for findings and limitations."])
    with (output_dir / "chunk_entropy.csv").open("w", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow(["chunk_number", "start_byte", "end_byte_exclusive", "size_bytes", "entropy_bits_per_byte"])
        for index, entropy in enumerate(chunk_entropies):
            start = index * CHUNK_SIZE
            size = min(CHUNK_SIZE, len(raw_data) - start)
            writer.writerow([index + 1, start, start + size, size, round(entropy, 6)])
    return report
