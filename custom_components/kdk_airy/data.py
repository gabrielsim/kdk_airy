"""Custom types for KDK Airy."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.loader import Integration

from .client import KdkHybridClient
from .coordinator import KdkAiryDataUpdateCoordinator

type KdkConfigEntry = ConfigEntry[KdkData]


@dataclass
class KdkData:
    """Data for the KDK Airy integration."""

    client: KdkHybridClient
    coordinator: KdkAiryDataUpdateCoordinator
    integration: Integration
