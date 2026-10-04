"""Shared helpers for discovery tests."""

from __future__ import annotations

import tempfile
import unittest

from maskhub.console.runtime import build_runtime
from maskhub.store.kvstore import RecordStore


class DiscoveryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        store = RecordStore(self._tmp.name)
        store.load()
        self.runtime = build_runtime(store)
        self.registry = self.runtime.discovery
        self.scanner = self.runtime.scanner

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def scan(self, dataset: str, columns: list[dict[str, object]]) -> dict[str, object]:
        return self.scanner.scan(dataset, columns)

    def verdict(self, dataset: str, field_name: str):
        return self.registry.get(dataset, field_name)
