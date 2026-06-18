# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""CLI entry point for the eval harness.

Usage:
    python -m eval.run --corpus eval/data/eval_corpus.json
    python -m eval.run --corpus eval/data/eval_corpus.json --limit 10
    python -m eval.run --corpus eval/data/eval_corpus.json --output results.json
    python -m eval.run --corpus eval/data/eval_corpus.json --model gemma4:latest
    python -m eval.run --corpus eval/data/eval_corpus.json --provider gemini --api-key <key>
    python -m eval.run --corpus eval/data/eval_corpus.json --provider gemini \
        --api-key <key> --model gemini-2.5-pro
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from eval.corpus.loader import load_corpus
from eval.corpus.schema import CorpusEntry, EvalResult
from eval.pipeline import evaluate_entry
from eval.report import print_report, save_json_report
from eval.scoring import compute_metrics
from src.infra.logging import configure_logging
from src.interfaces.llm_provider import LLMProvider
from src.llm.gemini_client import GeminiClient
from src.llm.ollama_client import OllamaClient


@click.command()
@click.option(
    "--corpus",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to eval_corpus.json",
)
@click.option(
    "--provider",
    default="ollama",
    type=click.Choice(["ollama", "gemini"], case_sensitive=False),
    show_default=True,
    help="LLM provider to use",
)
@click.option(
    "--model",
    default=None,
    help="Model name (default: gemma4:latest for ollama, gemini-2.5-flash for gemini)",
)
@click.option(
    "--limit",
    default=0,
    show_default=True,
    help="Max entries to evaluate (0 = all)",
)
@click.option(
    "--ids",
    default=None,
    help="Comma-separated alert_ids to evaluate (e.g. formbook-011,icedid-cs-004)",
)
@click.option(
    "--split",
    default=None,
    type=click.Choice(["dev", "held_out"], case_sensitive=False),
    help="Only evaluate entries tagged with this split (default: all entries)",
)
@click.option(
    "--output",
    default=None,
    type=click.Path(path_type=Path),
    help="Optional path to save JSON report",
)
@click.option(
    "--ollama-url",
    default="http://localhost:11434/api/chat",
    show_default=True,
    help="Ollama API base URL (ollama provider only)",
)
@click.option(
    "--api-key",
    default=None,
    envvar="GEMINI_API_KEY",
    help="Google AI Studio API key (gemini provider only; or set GEMINI_API_KEY env var)",
)
@click.option(
    "--timeout",
    default=300.0,
    show_default=True,
    help="Per-request LLM timeout in seconds",
)
@click.option(
    "--temperature",
    default=None,
    type=float,
    help="Sampling temperature (ollama and gemini providers). Omit to use the "
    "model/API default; pin to 0 for greedy/reproducible decoding. For gemini, "
    "temperature=0 also sets topK=1/topP=1 for maximally deterministic output.",
)
def main(
    corpus: Path,
    provider: str,
    model: str | None,
    limit: int,
    ids: str | None,
    split: str | None,
    output: Path | None,
    ollama_url: str,
    api_key: str | None,
    timeout: float,
    temperature: float | None,
) -> None:
    configure_logging("INFO")
    entries = load_corpus(corpus)
    if split:
        split = split.lower()
        entries = [e for e in entries if e.split == split]
    if ids:
        id_set = {i.strip() for i in ids.split(",")}
        entries = [e for e in entries if e.alert_id in id_set]
    if limit > 0:
        entries = entries[:limit]

    if provider == "gemini":
        if not api_key:
            raise click.UsageError(
                "--api-key (or GEMINI_API_KEY env var) is required for --provider gemini"
            )
        effective_model = model or "gemini-2.5-flash"
        client = GeminiClient(
            api_key=api_key, model=effective_model, temperature=temperature
        )
        temp_label = "API default" if temperature is None else f"{temperature:g}"
        click.echo(f"Loaded {len(entries)} corpus entries from {corpus}")
        click.echo(
            f"Provider: Gemini  Model: {effective_model}  Temperature: {temp_label}"
        )
    else:
        effective_model = model or "gemma4:e4b-it-q8_0"
        client = OllamaClient(
            model=effective_model,
            base_url=ollama_url,
            timeout=timeout,
            temperature=temperature,
        )
        temp_label = "model default" if temperature is None else f"{temperature:g}"
        click.echo(f"Loaded {len(entries)} corpus entries from {corpus}")
        click.echo(
            f"Provider: Ollama  Model: {effective_model}  URL: {ollama_url}  "
            f"Temperature: {temp_label}"
        )

    click.echo()
    results = asyncio.run(_evaluate_all(entries, client))

    metrics = compute_metrics(results)
    print_report(metrics, results)

    if output:
        save_json_report(metrics, results, output)

    # Exit 1 if below ship bar
    if metrics.verdict_accuracy < 0.80 or metrics.false_negative_rate > 0.05:
        sys.exit(1)


async def _evaluate_all(
    entries: list[CorpusEntry],
    client: LLMProvider,
) -> list[EvalResult]:
    results: list[EvalResult] = []
    with click.progressbar(
        entries, label="Evaluating", item_show_func=lambda e: e.alert_id if e else ""
    ) as bar:
        for entry in bar:
            result = await evaluate_entry(entry, client)
            results.append(result)
    return results


if __name__ == "__main__":
    main()
