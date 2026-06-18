# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Load the eval corpus JSON file into CorpusEntry objects."""
from __future__ import annotations

import json
from pathlib import Path

from eval.corpus.schema import CorpusEntry


def load_corpus(path: Path) -> list[CorpusEntry]:
    """Parse eval_corpus.json and return a list of CorpusEntry objects."""
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)

    entries = []
    for item in raw["entries"]:
        entries.append(CorpusEntry.model_validate(item))
    return entries
