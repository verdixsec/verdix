# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Suricata configuration reader.

Usage:
    from src.infra.suricata_config import read_config
    config = read_config("/host/suricata/config/suricata.yaml")
"""
from src.infra.suricata_config.models import SuricataConfig
from src.infra.suricata_config.reader import read_config

__all__ = ["SuricataConfig", "read_config"]
