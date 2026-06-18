# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for GeoIPClient using mocked geoip2 readers."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.enrichment.maxmind.client import GeoIPClient
from src.enrichment.models import (
    EnrichmentStatus,
    Indicator,
    IndicatorType,
)

_IP = Indicator(type=IndicatorType.IP, value="8.8.8.8")
_DOMAIN = Indicator(type=IndicatorType.DOMAIN, value="example.com")
_PRIVATE = Indicator(type=IndicatorType.IP, value="10.0.0.1")


def _make_reader(country_code="US", country_name="United States", asn=15169, asn_org="Google LLC"):
    """Build a minimal geoip2 reader mock."""
    reader = MagicMock()
    country_record = MagicMock()
    country_record.country.iso_code = country_code
    country_record.country.name = country_name
    reader.country.return_value = country_record

    asn_record = MagicMock()
    asn_record.autonomous_system_number = asn
    asn_record.autonomous_system_organization = asn_org
    reader.asn.return_value = asn_record
    return reader


async def test_domain_indicator_returns_not_configured() -> None:
    client = GeoIPClient(country_db_path="nonexistent", asn_db_path="nonexistent")
    result = await client.lookup(_DOMAIN)
    assert result.status == EnrichmentStatus.NOT_CONFIGURED


async def test_no_db_files_returns_not_configured() -> None:
    client = GeoIPClient(country_db_path="/no/such/file.mmdb", asn_db_path="/no/such/asn.mmdb")
    result = await client.lookup(_IP)
    assert result.status == EnrichmentStatus.NOT_CONFIGURED


async def test_country_and_asn_lookup_returns_contributed() -> None:
    client = GeoIPClient(country_db_path="/fake/country.mmdb", asn_db_path="/fake/asn.mmdb")
    mock_reader = _make_reader()

    with patch("os.path.isfile", return_value=True), \
         patch("geoip2.database.Reader", return_value=mock_reader):
        client._init_attempted = False
        result = await client.lookup(_IP)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.data["country_code"] == "US"
    assert result.data["asn"] == 15169
    assert result.data["asn_org"] == "Google LLC"
    assert "US" in result.summary
    assert "AS15169" in result.summary
    assert "Google LLC" in result.summary


async def test_country_only_still_contributed() -> None:
    """If only the country DB is present, ASN is absent but result is still CONTRIBUTED."""
    client = GeoIPClient(country_db_path="/fake/country.mmdb", asn_db_path="/no/asn.mmdb")

    country_reader = MagicMock()
    country_record = MagicMock()
    country_record.country.iso_code = "DE"
    country_record.country.name = "Germany"
    country_reader.country.return_value = country_record

    def fake_isfile(path):
        return "country" in path

    with patch("os.path.isfile", side_effect=fake_isfile), \
         patch("geoip2.database.Reader", return_value=country_reader):
        client._init_attempted = False
        result = await client.lookup(_IP)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.data["country_code"] == "DE"
    assert result.data["asn"] is None
    assert "DE" in result.summary


async def test_private_ip_returns_contributed_with_private_ip_summary() -> None:
    """Private IPs are not in GeoIP databases but the client IS configured.
    Returns CONTRIBUTED with 'Private IP' summary rather than NOT_CONFIGURED."""
    client = GeoIPClient(country_db_path="/fake/country.mmdb", asn_db_path="/fake/asn.mmdb")
    mock_reader = MagicMock()
    mock_reader.country.side_effect = Exception("not found")
    mock_reader.asn.side_effect = Exception("not found")

    with patch("os.path.isfile", return_value=True), \
         patch("geoip2.database.Reader", return_value=mock_reader):
        client._init_attempted = False
        result = await client.lookup(_PRIVATE)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.summary == "Private IP"
    assert result.data == {"note": "private_ip"}


async def test_asn_only_lookup_succeeds() -> None:
    client = GeoIPClient(country_db_path="/no/country.mmdb", asn_db_path="/fake/asn.mmdb")
    asn_reader = MagicMock()
    asn_record = MagicMock()
    asn_record.autonomous_system_number = 396356
    asn_record.autonomous_system_organization = "Frantech Solutions"
    asn_reader.asn.return_value = asn_record

    def fake_isfile(path):
        return "asn" in path

    with patch("os.path.isfile", side_effect=fake_isfile), \
         patch("geoip2.database.Reader", return_value=asn_reader):
        client._init_attempted = False
        result = await client.lookup(_IP)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert "AS396356" in result.summary
    assert "Frantech" in result.summary
