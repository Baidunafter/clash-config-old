"""Unit and end-to-end tests for the aggregator and the profile rule rendering.

Run: python -m unittest discover -s tools/ruleset-builder/tests -v
No network and no Mihomo binary are needed: downloads and MRS compilation are mocked.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "config-builder"))

import yaml  # noqa: E402

import build  # noqa: E402
import build_profiles  # noqa: E402
import source_utils  # noqa: E402


class PlainListParsing(unittest.TestCase):
    def test_keywords_regex_and_drops_are_classified(self):
        text = "\n".join([
            "# comment",
            "domain:example.com",
            "full:api.example.org",
            "plain.example.net",
            "keyword:deepl.",
            r"regexp:(^|\.)ec2-.+\.amazonaws\.com$",
            "include:other-list",
            "domain:xbox",
            "domain:keep.me @ads",
            "0.0.0.0 hosts.example.io",
        ])
        parsed = build.parse_plain_list_ex(text)
        self.assertEqual(parsed.domains, {"example.com", "api.example.org", "plain.example.net", "keep.me", "hosts.example.io"})
        self.assertEqual(parsed.keywords, {"deepl."})
        self.assertEqual(len(parsed.regexes), 1)
        self.assertEqual(dict(parsed.dropped), {"include": 1, "single_label": 1})
        self.assertEqual(parsed.notes["attributes_stripped"], 1)
        self.assertEqual(parsed.notes["full_broadened"], 1)

    def test_normalize_domain_compat(self):
        self.assertEqual(build.normalize_domain("*.Example.COM"), "example.com")
        self.assertIsNone(build.normalize_domain("keyword:foo"))
        self.assertIsNone(build.normalize_domain("localhost"))


class ClassicalParsing(unittest.TestCase):
    PAYLOAD = """
payload:
  - DOMAIN-SUFFIX,ea.com
  - DOMAIN,origin.ea.com
  - DOMAIN-KEYWORD,eaccess
  - DOMAIN-REGEX,^a{1,3}\\.ea\\.com$
  - IP-CIDR,1.2.3.0/24,no-resolve
  - PROCESS-NAME,EADesktop.exe
  - GEOIP,CN
"""

    def test_kinds(self):
        parsed = build.parse_classical_yaml_ex(self.PAYLOAD)
        self.assertEqual(parsed.domains, {"ea.com", "origin.ea.com"})
        self.assertEqual(parsed.keywords, {"eaccess"})
        self.assertEqual(len(parsed.regexes), 1)
        self.assertEqual(parsed.cidrs, {"1.2.3.0/24"})
        self.assertEqual(parsed.processes, {"PROCESS-NAME,EADesktop.exe"})
        self.assertEqual(dict(parsed.dropped), {"unsupported:GEOIP": 1})

    def test_process_rules_keep_their_kind_and_regexes_are_validated(self):
        text = "payload:\n  - PROCESS-NAME-REGEX,(?i)discord\n  - PROCESS-NAME,com.discord\n  - PROCESS-NAME-REGEX,([\n  - PROCESS-PATH,C:\\Apps\\x.exe\n"
        parsed = build.parse_classical_yaml_ex(text)
        self.assertEqual(parsed.processes, {"PROCESS-NAME-REGEX,(?i)discord", "PROCESS-NAME,com.discord", "PROCESS-PATH,C:\\Apps\\x.exe"})
        self.assertEqual(dict(parsed.dropped), {"invalid_regex": 1})

    def test_classical_file_lists_keywords_regexes_then_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x-classical.yaml"
            build.write_classical(path, {"kw"}, {"^a$"}, {"PROCESS-NAME,z.exe", "PROCESS-NAME,a.exe"})
            self.assertEqual(yaml.safe_load(path.read_text(encoding="utf-8"))["payload"],
                             ["DOMAIN-KEYWORD,kw", "DOMAIN-REGEX,^a$", "PROCESS-NAME,a.exe", "PROCESS-NAME,z.exe"])

    def test_missing_payload_is_an_error(self):
        with self.assertRaises(RuntimeError):
            build.parse_classical_yaml_ex("rules: []")


class MalwParsing(unittest.TestCase):
    HOSTS = "\n".join([
        "### dns.malw.link: hosts file",
        "# Последнее обновление: 11 октября 2026",
        "",
        "1.1.1.1 redirect.example.com",
        "# Linear",
        "1.1.1.1 linear.app",
        "# Блокировка",
        "0.0.0.0 ads.example.net tracker.example.net",
        "### end",
    ])

    def test_meta_lines_do_not_create_sections(self):
        sections, redirects = build.parse_malw_hosts(self.HOSTS)
        self.assertEqual(set(sections), {"__preamble__", "Linear", "Блокировка"})
        self.assertIn("redirect.example.com", sections["__preamble__"])
        self.assertEqual(sections["Блокировка"], {"ads.example.net", "tracker.example.net"})
        self.assertNotIn("ads.example.net", redirects)  # blocking entries are not redirects

    def test_alternatives_and_optional(self):
        sections, _ = build.parse_malw_hosts(self.HOSTS)
        values, label, optional = build.resolve_malw_entry(sections, ["Linear.app", "Linear"])
        self.assertEqual((values, label, optional), ({"linear.app"}, "Linear", False))
        values, label, optional = build.resolve_malw_entry(sections, "?Windsurf")
        self.assertEqual((values, label, optional), (set(), "Windsurf", True))

    def test_last_update_and_age(self):
        import datetime as dt
        self.assertEqual(source_utils.malw_last_update(self.HOSTS), "11 октября 2026")
        self.assertEqual(build.malw_age_days(self.HOSTS, dt.date(2026, 10, 14)), 3)


class Exclusions(unittest.TestCase):
    def test_exact_entry_removed_subdomains_kept(self):
        domains = {"google.com", "gemini.google.com", "stripe.com", "openai.com"}
        mapping = {"exclude_domains": {"blackmatrix7": ["google.com", "stripe.com"]}}
        removable = build.excludes_for(mapping, "blackmatrix7") & domains
        self.assertEqual(domains - removable, {"gemini.google.com", "openai.com"})

    def test_list_form_applies_to_every_source(self):
        mapping = {"exclude_domains": ["a.com"]}
        self.assertEqual(build.excludes_for(mapping, "itdog"), {"a.com"})
        self.assertEqual(build.excludes_for({"exclude_domains": {"itdog": ["a.com"]}}, "codelab"), set())


class ShrinkGuard(unittest.TestCase):
    PREV = {"domain": {"big": {"domains": 1000}, "small": {"domains": 10}}, "ip": {"net": {"cidrs": 100}}}
    GUARD = {"max_shrink_percent": 40, "min_previous_size": 50}

    def manifest(self, big, small=10, net=100):
        return {"domain": {"big": {"domains": big}, "small": {"domains": small}}, "ip": {"net": {"cidrs": net}}}

    def test_large_shrink_fails(self):
        errors = build.check_shrink(self.PREV, self.manifest(200), self.GUARD, set())
        self.assertEqual(len(errors), 1)
        self.assertIn("domain/big", errors[0])

    def test_small_shrink_and_tiny_sets_pass(self):
        self.assertEqual(build.check_shrink(self.PREV, self.manifest(700, small=1), self.GUARD, set()), [])

    def test_allow_list(self):
        self.assertEqual(build.check_shrink(self.PREV, self.manifest(5), self.GUARD, {"big"}), [])
        self.assertEqual(build.check_shrink(self.PREV, self.manifest(5), self.GUARD, {"domain/big"}), [])

    def test_ip_sets_are_checked(self):
        errors = build.check_shrink(self.PREV, self.manifest(1000, net=10), self.GUARD, set())
        self.assertTrue(errors and errors[0].startswith("ip/net"))


class EndToEnd(unittest.TestCase):
    """main() against a temporary repository with mocked upstreams."""

    CATEGORIES = """
services:
  alpha:
    itdog: [Services/alpha.lst]
    blackmatrix7: [Beta]
    exclude_domains:
      blackmatrix7: [parent.com]
  gone:
    optional: true
    malw: ["?Missing"]
categories:
  block:
    roscomvpn: [blk]
ip_categories: {}
"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        (root / "settings").mkdir()
        (root / "tools").mkdir()
        (root / "settings/repositories.yaml").write_text(
            "sources:\n"
            "  roscomvpn_geosite: {raw_base: 'https://rv.test/'}\n"
            "  itdog_allow_domains: {raw_base: 'https://itdog.test/'}\n"
            "  codelab_ruleset: {raw_base: 'https://codelab.test/'}\n"
            "  roscomvpn_geoip: {raw_base: 'https://rvip.test/'}\n"
            "  blackmatrix7: {raw_base: 'https://bm7.test/rule/'}\n"
            "  malw_hosts: {url: 'https://malw.test/hosts'}\n", encoding="utf-8")
        (root / "settings/build.yaml").write_text(
            "malw: {publish_host_overrides: false}\nguard: {max_shrink_percent: 40, min_previous_size: 5}\n"
            "conflicts: {direct_lists: [{source: roscomvpn, path: category-ru}]}\n", encoding="utf-8")
        (root / "settings/rules.yaml").write_text(
            "generated_targets: {alpha: G}\ngenerated_blocks: [block]\nordered_rules:\n- block: block\n- domain: alpha\n", encoding="utf-8")
        (root / "tools/categories.yaml").write_text(self.CATEGORIES, encoding="utf-8")
        (root / "settings/mirror.yaml").write_text(
            "mirror:\n"
            "  geo-priv: {source: roscomvpn_geosite, path: release/mihomo/priv.mrs}\n"
            "  ru-apps: {source: codelab_ruleset, path: ruleset/ru-apps.yaml}\n", encoding="utf-8")
        self.root = root
        self.files = self.default_files()
        patches = [
            mock.patch.object(build, "ROOT", root),
            mock.patch.object(build, "TOOL_DIR", root / "tools"),
            mock.patch.object(build, "download_text", side_effect=lambda url, timeout=45: self.fetch(url)),
            mock.patch.object(build, "download_bytes", side_effect=lambda url, timeout=60: self.fetch(url).encode("latin-1")),
            mock.patch.object(build, "compile_mrs", side_effect=self.fake_compile),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def fake_compile(mihomo, behavior, source, target):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())

    def default_files(self):
        alpha = "".join(f"a{i}.example.com\n" for i in range(30))
        beta = "payload:\n  - DOMAIN-SUFFIX,parent.com\n  - DOMAIN-SUFFIX,child.parent.com\n  - DOMAIN-KEYWORD,betakw\n  - PROCESS-NAME,beta.exe\n"
        blk = "domain:ads.example.net\nkeyword:tracker.\ndomain:a1.example.com\n"
        return {
            "https://itdog.test/Services/alpha.lst": alpha,
            "https://bm7.test/rule/Beta/Beta.yaml": beta,
            "https://rv.test/data/blk": blk,
            "https://rv.test/data/category-ru": "domain:a3.example.com\n",
            "https://rv.test/release/mihomo/priv.mrs": "\x28\xb5\x2f\xfdpayload-bytes",
            "https://codelab.test/ruleset/ru-apps.yaml": "payload:\n  - PROCESS-NAME,ru.sber.app\n",
            "https://malw.test/hosts": "# Последнее обновление: 1 января 2020\n# Other\n1.1.1.1 other.example.com\n",
        }

    def fetch(self, url):
        if url not in self.files:
            raise RuntimeError(f"HTTP 404: {url}")
        return self.files[url]

    def run_build(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = build.main(["--mihomo", "unused", *extra])
        return code, out.getvalue(), err.getvalue()

    def gen(self, rel):
        return self.root / "generated" / rel

    def test_successful_build_outputs(self):
        code, out, _ = self.run_build()
        self.assertEqual(code, 0)
        text = self.gen("source/domain/alpha.txt").read_text(encoding="utf-8")
        self.assertIn("+.child.parent.com", text)       # sub-domain kept
        self.assertNotIn("+.parent.com\n", text)         # exact parent removed
        self.assertTrue(self.gen("classical/alpha-classical.yaml").exists())
        self.assertIn("DOMAIN-KEYWORD,betakw", self.gen("classical/alpha-classical.yaml").read_text(encoding="utf-8"))
        self.assertIn("DOMAIN-KEYWORD,tracker.", self.gen("classical/block-classical.yaml").read_text(encoding="utf-8"))
        manifest = json.loads(self.gen("meta/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["skipped_optional"], ["gone"])
        self.assertEqual(manifest["domain"]["alpha"]["excluded"], 1)
        self.assertEqual(manifest["domain"]["alpha"]["classical"]["keywords"], 1)
        self.assertIn("PROCESS-NAME,beta.exe", self.gen("classical/alpha-classical.yaml").read_text(encoding="utf-8"))
        self.assertEqual(manifest["domain"]["alpha"]["classical"]["processes"], 1)
        losses = json.loads(self.gen("meta/losses.json").read_text(encoding="utf-8"))
        self.assertNotIn("services/alpha", losses)  # process rules are kept now, nothing is dropped
        self.assertIn("::warning::", out)
        self.assertIn("last updated", out)  # stale MALW warning

    def test_shrink_guard_blocks_and_keeps_previous_output(self):
        self.assertEqual(self.run_build()[0], 0)
        before = self.gen("source/domain/alpha.txt").read_text(encoding="utf-8")
        self.files["https://itdog.test/Services/alpha.lst"] = "a0.example.com\n"
        code, _, err = self.run_build()
        self.assertEqual(code, 2)
        self.assertIn("services/alpha".split("/")[1], err)
        self.assertIn("shrank", err)
        self.assertEqual(self.gen("source/domain/alpha.txt").read_text(encoding="utf-8"), before)  # untouched

    def test_allow_shrink_publishes(self):
        self.assertEqual(self.run_build()[0], 0)
        self.files["https://itdog.test/Services/alpha.lst"] = "a0.example.com\n"
        self.assertEqual(self.run_build("--allow-shrink", "alpha")[0], 0)
        self.assertNotIn("a5.example.com", self.gen("source/domain/alpha.txt").read_text(encoding="utf-8"))

    def test_conflict_report(self):
        code, out, _ = self.run_build()
        self.assertEqual(code, 0)
        report = json.loads(self.gen("meta/conflicts.json").read_text(encoding="utf-8"))
        self.assertEqual(report["direct_overlap"]["alpha"]["count"], 1)
        self.assertIn("a3.example.com", report["direct_overlap"]["alpha"]["examples"][0])
        self.assertNotIn("block", report["direct_overlap"])  # REJECT categories are not checked
        conflict, = report["target_conflicts"]
        self.assertEqual((conflict["winner"], conflict["winner_target"], conflict["loser"], conflict["loser_target"]),
                         ("block", "REJECT", "alpha", "G"))
        self.assertEqual(conflict["examples"], ["a1.example.com"])
        self.assertIn("alpha: 1 domains are also in the Russian direct lists", out)

    def test_unavailable_direct_list_is_only_a_warning(self):
        del self.files["https://rv.test/data/category-ru"]
        code, out, _ = self.run_build()
        self.assertEqual(code, 0)
        self.assertIn("conflict check: direct list", out)

    def test_mirror_files_are_copied_verbatim(self):
        self.assertEqual(self.run_build()[0], 0)
        self.assertEqual(self.gen("mirror/geo-priv.mrs").read_bytes(), b"\x28\xb5\x2f\xfdpayload-bytes")
        self.assertIn("ru.sber.app", self.gen("mirror/ru-apps.yaml").read_text(encoding="utf-8"))
        manifest = json.loads(self.gen("meta/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["mirror"]["ru-apps"]["file"], "generated/mirror/ru-apps.yaml")
        self.assertEqual(len(manifest["mirror"]["geo-priv"]["sha256"]), 64)

    def test_invalid_mirror_file_blocks_publication(self):
        self.files["https://rv.test/release/mihomo/priv.mrs"] = "<html>rate limited</html>"
        code, _, err = self.run_build()
        self.assertEqual(code, 2)
        self.assertIn("mirror/geo-priv", err)
        self.assertFalse(self.gen("mirror").exists())

    def test_empty_mirror_yaml_is_rejected(self):
        self.files["https://codelab.test/ruleset/ru-apps.yaml"] = "payload: []\n"
        code, _, err = self.run_build()
        self.assertEqual(code, 2)
        self.assertIn("no payload entries", err)

    def test_failed_run_never_publishes(self):
        del self.files["https://rv.test/data/blk"]
        code, _, err = self.run_build()
        self.assertEqual(code, 2)
        self.assertFalse(self.gen("domain").exists())
        self.assertTrue(self.gen("meta/errors.txt").exists())

    def test_stale_outputs_are_removed(self):
        self.assertEqual(self.run_build()[0], 0)
        stale = self.gen("domain/removed-category.mrs")
        stale.write_bytes(b"x")
        self.assertEqual(self.run_build()[0], 0)
        self.assertFalse(stale.exists())


class ProfileRules(unittest.TestCase):
    """Keyword/regex companions must follow the target of their base category."""

    def test_companion_rules_and_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings").mkdir()
            gen = root / "generated"
            for rel in ("domain/geoblock.mrs", "domain/block.mrs", "ip/none.mrs", "classical/geoblock-classical.yaml", "classical/block-classical.yaml"):
                (gen / rel).parent.mkdir(parents=True, exist_ok=True)
                (gen / rel).write_text("x", encoding="utf-8")
            (gen / "ip/none.mrs").unlink()
            (root / "settings/rules.yaml").write_text(
                "generated_targets: {geoblock: Геоблок}\n"
                "generated_blocks: [block]\n"
                "generated_ip_targets: {}\n"
                "ordered_rules:\n- block: block\n- domain: geoblock\n- MATCH,Все остальное\n", encoding="utf-8")
            with mock.patch.object(build_profiles, "SETTINGS", root / "settings"), mock.patch.object(build_profiles, "GENERATED", gen):
                rules = build_profiles.render_ordered_rules(set()).splitlines()
                self.assertEqual(rules, [
                    "rules:",
                    "  - RULE-SET,block,REJECT",
                    "  - RULE-SET,block-classical,REJECT",
                    "  - RULE-SET,geoblock,Геоблок",
                    "  - RULE-SET,geoblock-classical,Геоблок",
                    "  - MATCH,Все остальное",
                ])
                # An excluded category drops its companion rule and provider too.
                self.assertTrue(build_profiles._provider_is_excluded("geoblock-classical", {"geoblock"}))
                rules = build_profiles.render_ordered_rules({"geoblock"}).splitlines()
                self.assertNotIn("  - RULE-SET,geoblock-classical,Геоблок", rules)

    def test_unreferenced_classical_set_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings").mkdir()
            gen = root / "generated"
            (gen / "classical").mkdir(parents=True)
            (gen / "classical/orphan-classical.yaml").write_text("x", encoding="utf-8")
            (root / "settings/rules.yaml").write_text(
                "generated_targets: {}\ngenerated_blocks: []\ngenerated_ip_targets: {}\nordered_rules:\n- MATCH,X\n", encoding="utf-8")
            with mock.patch.object(build_profiles, "SETTINGS", root / "settings"), mock.patch.object(build_profiles, "GENERATED", gen):
                with self.assertRaises(RuntimeError) as ctx:
                    build_profiles.render_ordered_rules(set())
                self.assertIn("orphan-classical", str(ctx.exception))


class DnsResolution(unittest.TestCase):
    CFG = {
        "doh_provider": "one",
        "providers": {"one": {"doh": "https://one.example/dns-query", "bootstrap": "https://1.1.1.1/dns-query"},
                      "two": {"doh": "https://two.example/dns-query", "bootstrap": "https://2.2.2.2/dns-query"}},
        "ru_resolver": "main",
        "dns": {
            "enable": True,
            "default-nameserver": ["$BOOTSTRAP"],
            "nameserver": ["$DOH"],
            "proxy-server-nameserver": ["$DOH"],
            "nameserver-policy": {"rule-set:category-ru,whitelist": ["$RU_DNS"]},
        },
    }

    def cfg(self, **overrides):
        import copy
        value = copy.deepcopy(self.CFG)
        for key, item in overrides.items():
            value[key] = item
        return value

    def test_placeholders_are_expanded_and_warp_uses_the_main_resolver(self):
        dns, warp = build_profiles.resolve_dns(self.cfg(), set())
        self.assertEqual(dns["default-nameserver"], ["https://1.1.1.1/dns-query"])
        self.assertEqual(dns["nameserver"], ["https://one.example/dns-query"])
        self.assertEqual(warp, ["https://one.example/dns-query"])
        self.assertEqual(dns["nameserver-policy"]["rule-set:category-ru,whitelist"], ["https://one.example/dns-query"])

    def test_separate_ru_resolver(self):
        dns, _ = build_profiles.resolve_dns(self.cfg(ru_resolver="two"), set())
        self.assertEqual(dns["nameserver-policy"]["rule-set:category-ru,whitelist"], ["https://two.example/dns-query"])
        self.assertEqual(dns["nameserver"], ["https://one.example/dns-query"])

    def test_excluded_providers_leave_the_policy(self):
        dns, _ = build_profiles.resolve_dns(self.cfg(), {"whitelist"})
        self.assertIn("rule-set:category-ru", dns["nameserver-policy"])
        dns, _ = build_profiles.resolve_dns(self.cfg(), {"whitelist", "category-ru"})
        self.assertNotIn("nameserver-policy", dns)

    def test_plain_dns_is_rejected(self):
        for field, value in (("nameserver", ["8.8.8.8"]), ("default-nameserver", ["111.88.96.54"]), ("proxy-server-nameserver", ["tls://x"])):
            cfg = self.cfg()
            cfg["dns"][field] = value
            with self.assertRaises(RuntimeError, msg=field):
                build_profiles.resolve_dns(cfg, set())

    def test_several_resolvers_are_allowed_but_fallback_is_not(self):
        cfg = self.cfg()
        cfg["dns"]["nameserver"] = ["$DOH", "https://two.example/dns-query"]
        dns, warp = build_profiles.resolve_dns(cfg, set())
        self.assertEqual(dns["nameserver"], ["https://one.example/dns-query", "https://two.example/dns-query"])
        self.assertEqual(warp, dns["nameserver"])
        cfg = self.cfg()
        cfg["dns"]["fallback"] = ["https://two.example/dns-query"]
        with self.assertRaises(RuntimeError):
            build_profiles.resolve_dns(cfg, set())

    def test_doh_provider_may_be_a_list_and_every_placeholder_expands_to_all_servers(self):
        dns, warp = build_profiles.resolve_dns(self.cfg(doh_provider=["one", "two"]), set())
        self.assertEqual(dns["nameserver"], ["https://one.example/dns-query", "https://two.example/dns-query"])
        self.assertEqual(dns["proxy-server-nameserver"], dns["nameserver"])
        self.assertEqual(dns["default-nameserver"], ["https://1.1.1.1/dns-query", "https://2.2.2.2/dns-query"])
        self.assertEqual(dns["nameserver-policy"]["rule-set:category-ru,whitelist"], dns["nameserver"])
        self.assertEqual(warp, dns["nameserver"])

    def test_an_empty_resolver_list_is_an_error(self):
        with self.assertRaises(RuntimeError):
            build_profiles.resolve_dns(self.cfg(doh_provider=[]), set())

    def test_a_provider_without_bootstrap_cannot_be_a_main_resolver(self):
        cfg = self.cfg()
        cfg["providers"]["xbox"] = {"doh": "https://xbox.example/dns-query"}
        with self.assertRaises(RuntimeError):
            build_profiles.resolve_dns(cfg, set()) if False else build_profiles.resolve_dns(self.cfg(doh_provider=["one", "xbox"]) | {"providers": cfg["providers"]}, set())

    def gemini_cfg(self, **overrides):
        cfg = self.cfg(**overrides)
        cfg["providers"]["xbox"] = {"doh": "https://xbox.example/dns-query"}
        cfg["dns"]["nameserver-policy"] = {"rule-set:gemini": ["$GEMINI_DNS"], "rule-set:category-ru,whitelist": ["$RU_DNS"]}
        return cfg

    def test_gemini_domains_get_their_own_resolver(self):
        cfg = self.gemini_cfg(gemini_resolver="xbox")
        dns, warp = build_profiles.resolve_dns(cfg, set())
        self.assertEqual(dns["nameserver-policy"]["rule-set:gemini"], ["https://xbox.example/dns-query"])
        self.assertNotIn("https://xbox.example/dns-query", dns["nameserver"] + dns["default-nameserver"])  # only Gemini uses it
        self.assertEqual(warp, ["https://one.example/dns-query"])
        self.assertEqual(build_profiles.gemini_resolver_url(cfg), "https://xbox.example/dns-query")

    def test_without_a_gemini_resolver_its_policy_disappears(self):
        cfg = self.gemini_cfg()
        dns, _ = build_profiles.resolve_dns(cfg, set())
        self.assertNotIn("rule-set:gemini", dns["nameserver-policy"])
        self.assertIsNone(build_profiles.gemini_resolver_url(cfg))

    def test_the_gemini_policy_follows_exclusions_and_must_be_https(self):
        dns, _ = build_profiles.resolve_dns(self.gemini_cfg(gemini_resolver="xbox"), {"gemini"})
        self.assertNotIn("rule-set:gemini", dns["nameserver-policy"])
        cfg = self.gemini_cfg(gemini_resolver="xbox")
        cfg["providers"]["xbox"] = {"doh": "tls://xbox.example"}
        with self.assertRaises(RuntimeError):
            build_profiles.resolve_dns(cfg, set())
        with self.assertRaises(RuntimeError):
            build_profiles.resolve_dns(self.gemini_cfg(gemini_resolver="nope"), set())

    def test_unknown_provider_fails(self):
        with self.assertRaises(RuntimeError):
            build_profiles.resolve_dns(self.cfg(doh_provider="nope"), set())

    def test_committed_dns_settings_are_valid(self):
        import yaml
        repo = HERE.parents[2]
        cfg = yaml.safe_load((repo / "settings/dns.yaml").read_text(encoding="utf-8"))
        dns, warp = build_profiles.resolve_dns(cfg, set())
        self.assertEqual(dns["nameserver"], ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"])
        self.assertEqual(warp, dns["nameserver"])
        self.assertEqual(dns["nameserver-policy"]["rule-set:gemini"], ["https://xbox-dns.ru/dns-query"])
        every_server = dns["default-nameserver"] + dns["nameserver"] + dns["proxy-server-nameserver"]
        self.assertTrue(all(u.startswith("https://") for u in every_server))
        self.assertNotIn("https://xbox-dns.ru/dns-query", every_server)  # Xbox DNS serves Gemini only


class SourceUrls(unittest.TestCase):
    SOURCES = {"blackmatrix7": {"raw_base": "https://x/rule/Clash/"}, "roscomvpn_geosite": {"raw_base": "https://r/"}}

    def test_blackmatrix7_service_name_expands(self):
        self.assertEqual(source_utils.source_url(self.SOURCES, "blackmatrix7", "OpenAI"), "https://x/rule/Clash/OpenAI/OpenAI.yaml")
        self.assertEqual(source_utils.source_url(self.SOURCES, "blackmatrix7", "Game/Roblox"), "https://x/rule/Clash/Game/Roblox/Roblox.yaml")

    def test_roscomvpn_prefix(self):
        self.assertEqual(source_utils.source_url(self.SOURCES, "roscomvpn", "youtube"), "https://r/data/youtube")


if __name__ == "__main__":
    unittest.main()
