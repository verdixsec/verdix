# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Integration test: load the real eval corpus and validate shape."""
from pathlib import Path

import pytest

from eval.corpus.loader import load_corpus
from eval.corpus.schema import VerdictCategory

_CORPUS_PATH = Path(__file__).parent.parent / "data" / "eval_corpus.json"


@pytest.mark.skipif(not _CORPUS_PATH.exists(), reason="corpus file not found")
def test_load_corpus_count():
    entries = load_corpus(_CORPUS_PATH)
    assert len(entries) > 0


@pytest.mark.skipif(not _CORPUS_PATH.exists(), reason="corpus file not found")
def test_corpus_has_all_verdict_categories():
    entries = load_corpus(_CORPUS_PATH)
    verdicts = {e.ground_truth.verdict for e in entries}
    assert VerdictCategory.LIKELY_TP in verdicts
    assert VerdictCategory.LIKELY_FP in verdicts
    assert VerdictCategory.SUSPICIOUS_INVESTIGATE in verdicts


@pytest.mark.skipif(not _CORPUS_PATH.exists(), reason="corpus file not found")
def test_corpus_entries_have_raw_eve():
    entries = load_corpus(_CORPUS_PATH)
    for entry in entries:
        assert "event_type" in entry.raw_eve
        assert entry.raw_eve["event_type"] == "alert"
