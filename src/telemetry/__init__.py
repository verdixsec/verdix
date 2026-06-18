# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Feedback collection for Verdix.

Two user-initiated submission types, sent only when the analyst acts:
  - Feedback: free-text plus the context items the analyst chooses to include.
  - Deletion request: asks Verdix to delete data held for this installation.

There is no passive or periodic telemetry. All outbound calls go through the
shared httpx factory. No alert content, no IPs, no hostnames are ever collected.
"""
