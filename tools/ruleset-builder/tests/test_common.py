"""Tests for the shared HTTP helpers (retries, cache, prefetch)."""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import common  # noqa: E402


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x.test/f", code, "err", {}, None)


class Retries(unittest.TestCase):
    def test_transient_status_is_retried_with_backoff(self):
        calls, sleeps = [], []

        def opener(request, timeout):
            calls.append(1)
            if len(calls) < 3:
                raise http_error(503)
            return FakeResponse(b"ok")

        data = common.fetch_bytes("https://x.test/f", opener=opener, sleep=sleeps.append, backoff=1)
        self.assertEqual(data, b"ok")
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleeps, [1, 2])

    def test_not_found_fails_immediately(self):
        calls = []

        def opener(request, timeout):
            calls.append(1)
            raise http_error(404)

        with self.assertRaises(common.HttpStatusError) as ctx:
            common.fetch_bytes("https://x.test/f", opener=opener, sleep=lambda s: None)
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(len(calls), 1)
        self.assertEqual(str(ctx.exception), "HTTP 404: https://x.test/f")

    def test_network_errors_exhaust_retries(self):
        calls = []

        def opener(request, timeout):
            calls.append(1)
            raise urllib.error.URLError("boom")

        with self.assertRaises(common.FetchError) as ctx:
            common.fetch_bytes("https://x.test/f", opener=opener, sleep=lambda s: None, retries=2)
        self.assertEqual(len(calls), 3)
        self.assertIn("boom", str(ctx.exception))


class Cache(unittest.TestCase):
    def test_second_fetch_uses_the_cache(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"SOURCE_CACHE_DIR": tmp, "SOURCE_CACHE_TTL": "600"}):
            self.assertTrue(common.cache_enabled())
            calls = []

            def opener(request, timeout):
                calls.append(1)
                return FakeResponse(b"first")

            self.assertEqual(common.fetch_bytes("https://x.test/f", opener=opener), b"first")
            self.assertEqual(common.fetch_bytes("https://x.test/f", opener=opener), b"first")
            self.assertEqual(len(calls), 1)

    def test_expired_entry_is_refetched(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"SOURCE_CACHE_DIR": tmp, "SOURCE_CACHE_TTL": "0"}):
            calls = []

            def opener(request, timeout):
                calls.append(1)
                return FakeResponse(b"x")

            common.fetch_bytes("https://x.test/f", opener=opener)
            os.utime(next(Path(tmp).iterdir()), (1, 1))
            common.fetch_bytes("https://x.test/f", opener=opener)
            self.assertEqual(len(calls), 2)

    def test_cache_is_off_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SOURCE_CACHE_DIR", None)
            self.assertFalse(common.cache_enabled())


class Prefetch(unittest.TestCase):
    def test_errors_are_returned_not_raised(self):
        def fetch(url):
            if url.endswith("bad"):
                raise RuntimeError("HTTP 404")
            return b"x"

        result = common.prefetch(["https://x.test/ok", "https://x.test/bad", "https://x.test/ok"], fetch=fetch)
        self.assertEqual(set(result), {"https://x.test/ok", "https://x.test/bad"})
        self.assertIsNone(result["https://x.test/ok"])
        self.assertIsInstance(result["https://x.test/bad"], RuntimeError)

    def test_empty_input(self):
        self.assertEqual(common.prefetch([]), {})


if __name__ == "__main__":
    unittest.main()
