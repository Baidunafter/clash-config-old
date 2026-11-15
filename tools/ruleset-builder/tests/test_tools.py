"""Tests for settings_check, make_test_profile, report, update_mihomo and provider rendering."""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
for extra in (HERE.parent, REPO / "tools" / "config-builder", REPO / "tools"):
    sys.path.insert(0, str(extra))

import build_profiles  # noqa: E402
import conflicts  # noqa: E402
import explain_route  # noqa: E402
import make_test_profile  # noqa: E402
import report  # noqa: E402
import settings_check  # noqa: E402
import update_mihomo  # noqa: E402

SOURCES = {
    "itdog_allow_domains": {"raw_base": "https://i.test/"},
    "roscomvpn_geosite": {"raw_base": "https://r.test/"},
    "blackmatrix7": {"raw_base": "https://b.test/rule/"},
}


class ObsoleteFiles(unittest.TestCase):
    def test_leftovers_of_earlier_layouts_are_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(settings_check.obsolete_files(root), [])
            for rel in ("settings/tun-exclude-packages.yaml", "templates/WARPxALT.yaml", "ruleset-alt/user-exclude-alt.yaml", "settings/dns.yaml"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("x", encoding="utf-8")
            found = settings_check.obsolete_files(root)
            self.assertEqual(found, ["settings/tun-exclude-packages.yaml", "templates/WARPxALT.yaml", "ruleset-alt"])

    def test_obsolete_files_never_fail_the_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "templates").mkdir()
            (Path(tmp) / "templates/WARPxUNIVERSAL.yaml").write_text("x", encoding="utf-8")
            self.assertEqual(settings_check.check_profiles({"profiles": {}}, Path(tmp)), ["profiles.yaml: 'profiles' must be a non-empty mapping"])


class SettingsCheck(unittest.TestCase):
    def test_committed_settings_are_valid(self):
        self.assertEqual(settings_check.validate_all(REPO), [])

    def test_itdog_category_lists_are_never_rejected(self):
        """itdog Categories/*.lst are sites blocked in Russia or blocking Russia: they need a proxy, not REJECT."""
        categories = yaml.safe_load((REPO / "tools/ruleset-builder/categories.yaml").read_text(encoding="utf-8"))
        rules = yaml.safe_load((REPO / "settings/rules.yaml").read_text(encoding="utf-8"))
        rejected = set(rules.get("generated_blocks") or [])
        for group in ("services", "categories"):
            for name, mapping in (categories.get(group) or {}).items():
                itdog = (mapping or {}).get("itdog") or []
                if any(str(rel).startswith("Categories/") for rel in itdog):
                    self.assertNotIn(name, rejected, f"'{name}' comes from itdog Categories/ and must not be REJECT")

    def problems(self, categories):
        return settings_check.check_categories(categories, SOURCES)

    def test_valid_category_passes(self):
        self.assertEqual(self.problems({"categories": {"a": {
            "itdog": ["x.lst"], "malw": ["A", ["B", "C"], "?D"], "optional": True,
            "exclude_domains": {"blackmatrix7": ["g.com"]}}}}), [])

    def test_typos_are_reported(self):
        problems = self.problems({"categories": {
            "a": {"itdogg": ["x.lst"]},
            "b": {"itdog": "x.lst"},
            "c": {"optional": "yes", "itdog": ["x.lst"]},
            "d": {"itdog": ["x.lst"], "exclude_domains": {"nope": ["g.com"]}},
            "e": {},
        }})
        text = "\n".join(problems)
        for fragment in ("unknown key 'itdogg'", "itdog must be a list", "optional must be true/false", "unknown source 'nope'", "non-empty mapping"):
            self.assertIn(fragment, text)

    def test_duplicate_category_names(self):
        problems = self.problems({"services": {"a": {"itdog": ["x"]}}, "categories": {"a": {"itdog": ["y"]}}})
        self.assertTrue(any("both services and categories" in p for p in problems))

    def test_rules_cross_checks(self):
        categories = {"categories": {"games": {"itdog": ["x"]}}, "ip_categories": {"tg": {"itdog": ["y"]}}}
        ok = {"generated_targets": {"games": "G"}, "generated_ip_targets": {"tg": "T"}, "generated_blocks": [],
              "ordered_rules": ["MATCH,X", {"domain": "games"}, {"ip": "tg"}]}
        self.assertEqual(settings_check.check_rules(ok, categories), [])
        bad = {"generated_targets": {"ghost": "G"}, "generated_ip_targets": {}, "generated_blocks": [],
               "ordered_rules": [{"domain": "games"}, {"ip": "tg"}, {"oops": "x"}]}
        text = "\n".join(settings_check.check_rules(bad, categories))
        self.assertIn("generated_targets.ghost", text)
        self.assertIn("'domain: games' has no target", text)
        self.assertIn("'ip: tg' has no target", text)
        self.assertIn("ordered_rules[2]", text)

    def test_build_settings(self):
        self.assertTrue(settings_check.check_build({"mihomo": {"version": "v1"}}))
        good = {"mihomo": {"version": "v1", "asset": "a", "sha256": "s"}, "guard": {"max_shrink_percent": 40, "allow_shrink": []}}
        self.assertEqual(settings_check.check_build(good), [])
        self.assertTrue(settings_check.check_build({**good, "guard": {"max_shrink_percent": 0}}))

    def test_mirror_references(self):
        problems = settings_check.check_mirror(
            {"mirror": {"m": {"source": "roscomvpn_geosite", "path": "release/x.mrs"}}},
            {"static": [{"name": "a", "behavior": "domain", "mirror": "missing"}, {"name": "b", "behavior": "domain"}]}, SOURCES)
        text = "\n".join(problems)
        self.assertIn("unknown mirror 'missing'", text)
        self.assertIn("needs mirror or url+path", text)


class OfflineProfile(unittest.TestCase):
    BASE = "https://raw.example/repo/main"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        (self.root / "generated/domain").mkdir(parents=True)
        (self.root / "generated/domain/a.mrs").write_bytes(b"mrs")
        (self.root / "profiles/p").mkdir(parents=True)
        (self.root / "profiles/p/user-exclude.yaml").write_text("payload: []\n", encoding="utf-8")
        self.profile = Path(self.tmp.name) / "P.yaml"

    def write_profile(self, providers):
        self.profile.write_text(yaml.safe_dump({"proxies": [], "rule-providers": providers}), encoding="utf-8")

    def test_private_providers_become_local_files(self):
        self.write_profile({
            "a": {"type": "http", "behavior": "domain", "format": "mrs", "url": f"{self.BASE}/generated/domain/a.mrs",
                  "path": "./ruleset/a.mrs", "interval": 86400, "header": {"Authorization": ["token x"]}},
            "u": {"type": "http", "behavior": "classical", "url": f"{self.BASE}/profiles/p/user-exclude.yaml", "path": "./u.yaml"},
            "third": {"type": "http", "behavior": "domain", "url": "https://other.example/x.mrs", "path": "./x.mrs"},
        })
        out = Path(self.tmp.name) / "out"
        config = make_test_profile.make_offline_profile(self.profile, self.root, out, self.BASE + "/")
        data = yaml.safe_load(config.read_text(encoding="utf-8"))["rule-providers"]
        self.assertEqual((data["a"]["type"], data["a"]["path"]), ("file", "./generated/domain/a.mrs"))
        self.assertNotIn("url", data["a"])
        self.assertNotIn("header", data["a"])
        self.assertEqual(data["u"]["path"], "./profiles/p/user-exclude.yaml")
        self.assertEqual(data["third"]["type"], "http")  # third-party stays remote
        self.assertTrue((out / "generated/domain/a.mrs").is_file())

    def test_missing_local_file_is_an_error(self):
        self.write_profile({"a": {"type": "http", "behavior": "domain", "url": f"{self.BASE}/generated/domain/missing.mrs", "path": "./m"}})
        with self.assertRaises(RuntimeError):
            make_test_profile.make_offline_profile(self.profile, self.root, Path(self.tmp.name) / "out", self.BASE)


class ProviderRendering(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for rel in ("generated/domain/a.mrs", "generated/ip/b.mrs", "generated/classical/a-classical.yaml", "generated/mirror/ru-apps.yaml", "generated/mirror/category-ru.mrs"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("x", encoding="utf-8")
        (root / "settings").mkdir()
        (root / "settings/rule-providers.yaml").write_text(yaml.safe_dump({"static": [
            {"name": "category-ru", "behavior": "domain", "format": "mrs", "mirror": "category-ru"},
            {"name": "ru-apps", "behavior": "classical", "format": "yaml", "mirror": "ru-apps"},
            {"name": "legacy", "behavior": "domain", "format": "text", "url": "https://x.test/l.lst", "path": "./l.lst", "interval": "default"},
        ]}), encoding="utf-8")
        self.root = root

    def render(self, profile, excluded=frozenset()):
        with mock.patch.object(build_profiles, "SETTINGS", self.root / "settings"), mock.patch.object(build_profiles, "GENERATED", self.root / "generated"):
            text = build_profiles.render_providers(profile, {"runtime": {}}, "https://raw.example/repo", set(excluded))
        return yaml.safe_load("x-default-interval: &default-interval 86400\nx-auth: &github-auth-header {Authorization: [t]}\n" + text)["rule-providers"]

    def test_mirror_generated_classical_and_user_providers(self):
        providers = self.render({"user_rules_dir": "profiles/alt"})
        self.assertEqual(providers["category-ru"]["url"], "https://raw.example/repo/generated/mirror/category-ru.mrs")
        self.assertEqual(providers["category-ru"]["path"], "./ruleset/mirror-category-ru.mrs")
        self.assertIn("header", providers["ru-apps"])
        self.assertEqual(providers["ru-apps"]["behavior"], "classical")
        self.assertEqual(providers["a-classical"]["behavior"], "classical")
        self.assertEqual(providers["b-ip"]["behavior"], "ipcidr")
        self.assertEqual(providers["user-exclude"]["url"], "https://raw.example/repo/profiles/alt/user-exclude.yaml")
        self.assertEqual(providers["user-exclude"]["path"], "./ruleset/user-exclude-alt.yaml")
        self.assertEqual(providers["legacy"]["interval"], 86400)
        self.assertNotIn("header", providers["legacy"])

    def test_exclusions_apply_to_mirror_and_user_providers(self):
        providers = self.render({"user_rules_dir": "profiles/alt"}, {"ru-apps", "user-geo-block"})
        self.assertNotIn("ru-apps", providers)
        self.assertNotIn("user-geo-block", providers)
        self.assertIn("user-exclude", providers)

    def test_missing_mirror_file_is_an_error(self):
        (self.root / "generated/mirror/ru-apps.yaml").unlink()
        with self.assertRaises(RuntimeError):
            self.render({"user_rules_dir": "profiles/alt"})

    def test_user_rules_dir_is_required(self):
        with self.assertRaises(RuntimeError):
            build_profiles.user_rules_dir({})


class Conflicts(unittest.TestCase):
    def test_covered_by_checks_the_entry_and_its_parents(self):
        direct = {"yandex.ru", "sber.ru"}
        self.assertEqual(conflicts.covered_by("yandex.ru", direct), "yandex.ru")
        self.assertEqual(conflicts.covered_by("mail.yandex.ru", direct), "yandex.ru")
        self.assertIsNone(conflicts.covered_by("notyandex.ru", direct))
        self.assertIsNone(conflicts.covered_by("example.ru", {"ru"}))  # a bare TLD never matches

    def test_direct_overlap_skips_direct_and_reject_targets(self):
        sets = {"a": {"x.yandex.ru", "ok.com"}, "b": {"x.yandex.ru"}, "c": {"x.yandex.ru"}}
        result = conflicts.direct_overlap(sets, {"a": "Геоблок", "b": "DIRECT", "c": "REJECT"}, {"yandex.ru"})
        self.assertEqual(list(result), ["a"])
        self.assertEqual(result["a"]["count"], 1)

    def test_target_conflicts_follow_rule_order_and_ignore_equal_targets(self):
        sets = {"first": {"d1.com", "d2.com", "same.com"}, "second": {"d1.com", "same.com"}, "third": {"d2.com"}, "unused": {"d1.com"}}
        targets = {"first": "A", "second": "B", "third": "A", "unused": "C"}
        order = [("first", "domain"), ("second", "domain"), ("third", "domain")]
        rows = conflicts.target_conflicts(sets, order, targets)
        self.assertEqual([(r["winner"], r["loser"], r["count"]) for r in rows], [("first", "second", 2)])

    def test_equal_targets_do_not_conflict(self):
        sets = {"x": {"d.com"}, "y": {"d.com"}}
        self.assertEqual(conflicts.target_conflicts(sets, [("x", "domain"), ("y", "domain")], {"x": "A", "y": "A"}), [])

    def test_rule_order_and_targets(self):
        rules = {"generated_targets": {"a": "G"}, "generated_blocks": ["blk"],
                 "ordered_rules": ["MATCH,X", {"block": "blk"}, {"ip": "a"}, {"domain": "a"}]}
        self.assertEqual(conflicts.rule_order(rules["ordered_rules"]), [("blk", "block"), ("a", "domain")])
        self.assertEqual(conflicts.category_targets(rules), {"a": "G", "blk": "REJECT"})


class RuleTargets(unittest.TestCase):
    def test_rule_target_parsing(self):
        self.assertEqual(settings_check.rule_target("RULE-SET,x,Геоблок,no-resolve"), "Геоблок")
        self.assertEqual(settings_check.rule_target("DOMAIN-SUFFIX,a.com,DIRECT"), "DIRECT")
        self.assertEqual(settings_check.rule_target("AND,((NETWORK,udp),(RULE-SET,d)),Discord"), "Discord")
        self.assertEqual(settings_check.rule_target("MATCH,Все остальное"), "Все остальное")
        self.assertIsNone(settings_check.rule_target("garbage"))

    def test_unknown_group_is_reported(self):
        rules = {"generated_targets": {"a": "AI", "b": "Typo"}, "generated_ip_targets": {"c": "DIRECT"},
                 "ordered_rules": ["MATCH,AI", "RULE-SET,x,Oops,no-resolve", {"domain": "a"}]}
        problems = settings_check.check_rule_targets(rules, {"AI"})
        text = "\n".join(problems)
        self.assertIn("generated_targets.b points at 'Typo'", text)
        self.assertIn("ordered_rules[1] points at 'Oops'", text)
        self.assertEqual(len(problems), 2)

    def test_committed_rules_only_use_real_groups(self):
        profiles_cfg = yaml.safe_load((REPO / "settings/profiles.yaml").read_text(encoding="utf-8"))
        groups = settings_check.template_groups(profiles_cfg, REPO)
        self.assertIn("AI", groups)
        rules = yaml.safe_load((REPO / "settings/rules.yaml").read_text(encoding="utf-8"))
        self.assertEqual(settings_check.check_rule_targets(rules, groups), [])


class ExcludePackages(unittest.TestCase):
    """tun.exclude-package-url: the client downloads the list of apps that bypass the VPN."""

    def write(self, text):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name) / "exclude-from-vpn.txt"
        path.write_text(text, encoding="utf-8")
        return path

    def test_names_are_read_one_per_line(self):
        path = self.write("ru.rostel\n\ncom.gnivts.selfemployed\n")
        self.assertEqual(build_profiles.load_package_list(path), ["ru.rostel", "com.gnivts.selfemployed"])

    def test_missing_or_empty_file_means_no_packages(self):
        self.assertEqual(build_profiles.load_package_list(Path("/nonexistent/x.txt")), [])
        self.assertEqual(build_profiles.load_package_list(self.write("\n\n")), [])

    def test_comments_and_malformed_names_are_errors(self):
        # the client reads every line as a package name, so a comment would be a wrong package
        for bad in ("# Gosuslugi", "ru.rostel  # Gosuslugi", "notapackage", "com..double", "1com.example", "com.exa mple"):
            with self.assertRaises(RuntimeError, msg=bad):
                build_profiles.load_package_list(self.write(f"ru.rostel\n{bad}\n"))

    def test_url_carries_the_credentials_of_the_profile_link(self):
        url = build_profiles.package_list_url("https://raw.githubusercontent.com/owner/repo/refs/heads/main", "owner", "tok_en", "packages/exclude-from-vpn.txt")
        self.assertEqual(url, "https://owner:tok_en@raw.githubusercontent.com/owner/repo/refs/heads/main/packages/exclude-from-vpn.txt")

    def test_credentials_are_percent_encoded(self):
        url = build_profiles.package_list_url("https://h.example/base", "o@wner", "t:o/k", "p.txt")
        self.assertEqual(url, "https://o%40wner:t%3Ao%2Fk@h.example/base/p.txt")

    def test_tun_gets_the_url_after_its_own_settings(self):
        tun = {"enable": True, "strict-route": True}
        result = build_profiles.tun_with_package_url(tun, "https://x.example/p.txt")
        self.assertEqual(list(result), ["enable", "strict-route", "exclude-package-url"])
        self.assertNotIn("exclude-package-url", tun)  # the input is not modified

    def test_a_url_already_in_tun_yaml_wins(self):
        result = build_profiles.tun_with_package_url({"exclude-package-url": "https://public.example/p.txt"}, "https://private.example/p.txt")
        self.assertEqual(result["exclude-package-url"], "https://public.example/p.txt")

    def test_no_url_adds_no_key_and_names_are_never_inlined(self):
        self.assertNotIn("exclude-package-url", build_profiles.tun_with_package_url({"enable": True}, None))
        result = build_profiles.tun_with_package_url({"enable": True}, "https://x.example/p.txt")
        self.assertNotIn("exclude-package", result)

    def test_rendered_tun_block_is_valid_yaml(self):
        text = build_profiles.render_yaml_block({"tun": build_profiles.tun_with_package_url({"enable": True}, "https://o:t@x.example/p.txt")})
        self.assertEqual(yaml.safe_load(text)["tun"]["exclude-package-url"], "https://o:t@x.example/p.txt")

    def test_committed_file_is_valid_and_keeps_the_required_apps(self):
        # the list is the owner's to extend: only the apps it was created for are required
        packages = build_profiles.load_package_list(REPO / "packages/exclude-from-vpn.txt")
        for required in ("com.gnivts.selfemployed", "ru.rostel", "com.programmisty.emiasapp"):
            self.assertIn(required, packages)
        self.assertEqual(len(packages), len(set(packages)), "duplicate package names")
        self.assertEqual(settings_check.check_package_list(REPO / "packages/exclude-from-vpn.txt"), [])

    def test_settings_check_reports_comments_bad_and_duplicate_names(self):
        problems = settings_check.check_package_list(self.write("ru.rostel\nru.rostel\n# note\nnope\n"))
        text = "\n".join(problems)
        self.assertIn("'ru.rostel' is listed twice", text)
        self.assertIn("'# note' is not an Android package name", text)
        self.assertIn("'nope' is not an Android package name", text)
        self.assertEqual(settings_check.check_package_list(Path("/nonexistent/x.txt")), [])


class VideoGroup(unittest.TestCase):
    def setUp(self):
        self.rules = yaml.safe_load((REPO / "settings/rules.yaml").read_text(encoding="utf-8"))
        self.order = [next(iter(e.values())) for e in self.rules["ordered_rules"] if isinstance(e, dict)]
        template = yaml.safe_load((REPO / "templates/profile.yaml").read_text(encoding="utf-8"))
        self.groups = {g["name"]: g for g in template["proxy-groups"]}

    def test_streaming_and_netflix_have_their_own_group(self):
        for name in ("netflix", "streaming"):
            self.assertEqual(self.rules["generated_targets"][name], "Видео")
        self.assertIn("Видео", self.groups)
        self.assertEqual(self.groups["Видео"]["type"], "select")

    def test_geoblock_no_longer_carries_the_streaming_traffic(self):
        self.assertNotIn("Видео", [v for k, v in self.rules["generated_targets"].items() if k not in ("netflix", "streaming")])

    def test_video_data_is_direct_and_comes_before_the_streaming_categories(self):
        self.assertEqual(self.rules["generated_targets"]["bulk-direct-video"], "DIRECT")
        for name in ("netflix", "streaming"):
            self.assertLess(self.order.index("bulk-direct-video"), self.order.index(name))
        text = (REPO / "tools/ruleset-builder/lists/bulk-direct-video.txt").read_text(encoding="utf-8")
        self.assertIn("domain:nflxvideo.net", text)

    def test_new_group_has_the_same_options_as_the_other_category_groups(self):
        self.assertEqual(self.groups["Видео"]["proxies"], self.groups["YouTube"]["proxies"])


class GithubRouting(unittest.TestCase):
    def test_github_uses_the_cloudflare_group(self):
        rules = yaml.safe_load((REPO / "settings/rules.yaml").read_text(encoding="utf-8"))
        self.assertEqual(rules["generated_targets"]["github"], "Cloudflare")
        template = yaml.safe_load((REPO / "templates/profile.yaml").read_text(encoding="utf-8"))
        self.assertIn("Cloudflare", [g["name"] for g in template["proxy-groups"]])


class GeminiGroup(unittest.TestCase):
    def setUp(self):
        template = yaml.safe_load((REPO / "templates/profile.yaml").read_text(encoding="utf-8"))
        self.group = {g["name"]: g for g in template["proxy-groups"]}["Gemini"]

    def test_default_is_direct_and_copies_are_selectable(self):
        self.assertEqual(self.group["type"], "select")
        self.assertEqual(self.group["proxies"][0], "🔓 Без VPN")  # the first entry is the default
        self.assertTrue(re.search(self.group["filter"], "[GM] 🇳🇱 Нидерланды"))
        self.assertTrue(re.search(self.group["filter"], "[GM MQ] 🇳🇱 Нидерланды"))
        self.assertTrue(re.search(self.group["filter"], "[🌍] 🇳🇱 Нидерланды"))  # plain nodes stay available

    def test_copies_are_invisible_to_every_other_group(self):
        template = yaml.safe_load((REPO / "templates/profile.yaml").read_text(encoding="utf-8"))
        for group in template["proxy-groups"]:
            if group["name"] == "Gemini" or not group.get("filter"):
                continue
            for copy_name in ("[GM] 🇳🇱 Нидерланды", "[GM MQ] 🇳🇱 Нидерланды", "[GM] FRA #1:4500", "[GM] WARP-MASQUE QUIC"):
                self.assertFalse(re.search(group["filter"], copy_name), f"{group['name']} would list {copy_name}")


class ProcessRules(unittest.TestCase):
    def test_discord_and_tiktok_sources_carry_process_rules_upstream(self):
        categories = yaml.safe_load((REPO / "tools/ruleset-builder/categories.yaml").read_text(encoding="utf-8"))
        for name in ("discord", "tiktok"):
            self.assertIn(f"ruleset/{name}.yaml", categories["services"][name]["codelab"])
        # the companion rule exists for every category that has a classical file, with the category's target
        rules = yaml.safe_load((REPO / "settings/rules.yaml").read_text(encoding="utf-8"))
        self.assertIn("discord", rules["generated_targets"])
        self.assertIn("tiktok", rules["generated_targets"])


class GoogleRouting(unittest.TestCase):
    """The Google design: one exit for the session, no proxy for static and bulk traffic."""

    def setUp(self):
        self.rules = yaml.safe_load((REPO / "settings/rules.yaml").read_text(encoding="utf-8"))
        self.order = [next(iter(e.values())) for e in self.rules["ordered_rules"] if isinstance(e, dict)]
        self.targets = self.rules["generated_targets"]

    def test_bulk_is_direct_and_comes_before_core(self):
        self.assertEqual(self.targets["google-bulk"], "DIRECT")
        self.assertEqual(self.targets["google-core"], "AI")
        self.assertLess(self.order.index("google-bulk"), self.order.index("google-core"))

    def test_no_separate_google_service_categories_remain(self):
        # google-play and the google-meet domain list were fully covered by google-core
        for name in ("google-play", "google-meet"):
            self.assertNotIn(name, self.targets)
            self.assertNotIn({"domain": name}, self.rules["ordered_rules"])
        self.assertEqual(self.rules["generated_ip_targets"]["google-meet"], "AI")  # Meet media still shares the AI exit

    def test_gemini_has_its_own_group_and_precedes_bulk_and_core(self):
        self.assertEqual(self.targets["gemini"], "Gemini")
        self.assertLess(self.order.index("gemini"), self.order.index("google-bulk"))
        self.assertLess(self.order.index("gemini"), self.order.index("google-core"))
        self.assertNotIn("google-gemini", self.targets)
        lists = REPO / "tools/ruleset-builder/lists"
        gemini = [l for l in (lists / "gemini.txt").read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
        for entry in ("domain:gemini.google.com", "domain:gemini.gstatic.com", "domain:generativelanguage.googleapis.com"):
            self.assertIn(entry, gemini)
        core = (lists / "google-core.txt").read_text(encoding="utf-8")
        self.assertNotIn("domain:gemini.google\n", core)  # one owner per entry

    def test_bulk_precedes_youtube_which_keeps_its_own_group(self):
        # youtube lists contain googleusercontent.com / gvt1.com; bulk must win over them
        self.assertLess(self.order.index("google-bulk"), self.order.index("youtube"))
        self.assertLess(self.order.index("youtube"), self.order.index("google-core"))
        self.assertEqual(self.targets["youtube"], "YouTube")
        bulk = (REPO / "tools/ruleset-builder/lists/google-bulk.txt").read_text(encoding="utf-8")
        entries = [line for line in bulk.splitlines() if line.strip() and not line.startswith("#")]
        for video in ("googlevideo.com", "ytimg.com", "youtube.com"):
            self.assertFalse([e for e in entries if video in e], video)

    def test_no_static_rule_shadows_the_design(self):
        static = [e for e in self.rules["ordered_rules"] if isinstance(e, str)]
        self.assertFalse([e for e in static if e.startswith("DOMAIN-SUFFIX,google.com") or e.startswith("DOMAIN-SUFFIX,googleapis.com") or e.startswith("DOMAIN-SUFFIX,gstatic.com")])

    def test_local_lists(self):
        lists = REPO / "tools/ruleset-builder/lists"
        core = (lists / "google-core.txt").read_text(encoding="utf-8")
        bulk = (lists / "google-bulk.txt").read_text(encoding="utf-8")
        for entry in ("domain:google.com", "domain:googleapis.com"):
            self.assertIn(entry, core)
        for entry in ("domain:gstatic.com", "domain:storage.googleapis.com", "domain:dl.google.com", "keyword:mtalk.google.com"):
            self.assertIn(entry, bulk)
        self.assertFalse([l for l in core.splitlines() if "youtube" in l and not l.startswith("#")])


class NodeVisibility(unittest.TestCase):
    """Every group that a category routes to offers every node; saving traffic is done by category assignment."""

    CATEGORY_GROUPS = ("🛸 LOCAL-PROXY", "Обход качества Twitch", "Игры", "YouTube", "Видео", "Discord", "Telegram", "Meta",
                       "Геоблок", "AI", "Torrent", "Все остальное")

    def setUp(self):
        template = yaml.safe_load((REPO / "templates/profile.yaml").read_text(encoding="utf-8"))
        self.groups = {g["name"]: g for g in template["proxy-groups"]}

    def test_category_groups_list_every_endpoint_type_and_exclude_nothing(self):
        for name in self.CATEGORY_GROUPS:
            group = self.groups[name]
            for marker in ("🌍", "⭐", "🎭"):
                self.assertIn(marker, group["filter"], f"{name} must list {marker} nodes")
            self.assertNotIn("exclude-filter", group, f"{name} must not hide any node")

    def test_relay_group_shows_all_geo_nodes(self):
        self.assertNotIn("exclude-filter", self.groups["Relay-сервера"])

    def test_only_the_auto_select_group_skips_traffic_limited_nodes(self):
        self.assertEqual(self.groups["🌍 Авто"]["exclude-filter"], "TEL")
        others = [n for n, g in self.groups.items() if "exclude-filter" in g and n != "🌍 Авто"]
        self.assertEqual(others, [])

    def test_a_profile_lists_every_geo_node_of_the_source_file(self):
        geo = yaml.safe_load((REPO / "proxies/geo-endpoint.yaml").read_text(encoding="utf-8"))["proxies"]
        self.assertGreaterEqual(len(geo), 10)
        self.assertTrue(any("TEL" in str(n["name"]) for n in geo))


class Ipv6AndBulkRules(unittest.TestCase):
    def setUp(self):
        self.rules = yaml.safe_load((REPO / "settings/rules.yaml").read_text(encoding="utf-8"))["ordered_rules"]

    def index(self, entry):
        return self.rules.index(entry)

    def test_ipv6_is_rejected_after_the_ranges_that_must_survive_and_before_domain_categories(self):
        reject = self.index("IP-CIDR6,::/0,REJECT,no-resolve")
        for survivor in ({"ip": "telegram"}, "RULE-SET,private-ips,DIRECT,no-resolve", "RULE-SET,direct-ips,DIRECT,no-resolve"):
            self.assertLess(self.index(survivor), reject, survivor)
        for later in ({"domain": "google-core"}, {"domain": "ai"}, {"domain": "geoblock"}, {"domain": "youtube"}):
            self.assertLess(reject, self.index(later), later)

    def test_ipv6_rule_passes_the_group_check(self):
        self.assertEqual(settings_check.rule_target("IP-CIDR6,::/0,REJECT,no-resolve"), "REJECT")

    def test_bulk_direct_precedes_the_categories_that_contain_its_hosts(self):
        bulk = self.index({"domain": "bulk-direct"})
        for name in ("apple", "steam", "epic-games"):
            self.assertLess(bulk, self.index({"domain": name}), name)

    def test_bulk_direct_list_covers_the_known_heavy_hosts(self):
        text = (REPO / "tools/ruleset-builder/lists/bulk-direct.txt").read_text(encoding="utf-8")
        for entry in ("domain:cdn-apple.com", "domain:steamcontent.com", "domain:download.epicgames.com",
                      "domain:cdn-lfs.hf.co", "domain:registry-1.docker.io", "domain:download.nvidia.com"):
            self.assertIn(entry, text)
        entries = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
        for site in ("huggingface.co", "docker.com", "hub.docker.com", "auth.docker.io"):
            self.assertNotIn(f"domain:{site}", entries)  # the sites and sign-in stay in their categories
        self.assertEqual(yaml.safe_load((REPO / "settings/rules.yaml").read_text(encoding="utf-8"))["generated_targets"]["bulk-direct"], "DIRECT")


class ExplainRoute(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "generated/source/domain").mkdir(parents=True)
        (self.root / "generated/classical").mkdir(parents=True)
        (self.root / "profiles/p").mkdir(parents=True)
        (self.root / "generated/source/domain/core.txt").write_text("+.google.com\n", encoding="utf-8")
        (self.root / "generated/source/domain/bulk.txt").write_text("+.gstatic.com\n+.storage.googleapis.com\n", encoding="utf-8")
        (self.root / "generated/classical/bulk-classical.yaml").write_text("payload:\n- DOMAIN-KEYWORD,mtalk.google.com\n- DOMAIN-REGEX,^cdn[0-9]\\.example\\.com$\n", encoding="utf-8")
        (self.root / "profiles/p/user-exclude.yaml").write_text("payload:\n- DOMAIN-SUFFIX,mine.example\n", encoding="utf-8")
        base = "https://raw.example/repo/refs/heads/main"
        self.profile = {
            "rule-providers": {
                "user-exclude": {"behavior": "classical", "url": f"{base}/profiles/p/user-exclude.yaml"},
                "ru": {"behavior": "domain", "format": "mrs", "url": f"{base}/generated/mirror/ru.mrs"},
                "bulk": {"behavior": "domain", "format": "mrs", "url": f"{base}/generated/domain/bulk.mrs"},
                "bulk-classical": {"behavior": "classical", "url": f"{base}/generated/classical/bulk-classical.yaml"},
                "core": {"behavior": "domain", "format": "mrs", "url": f"{base}/generated/domain/core.mrs"},
                "net": {"behavior": "ipcidr", "format": "mrs", "url": f"{base}/generated/ip/net.mrs"},
            },
            "rules": ["RULE-SET,user-exclude,DIRECT", "RULE-SET,net,Telegram,no-resolve", "RULE-SET,bulk,DIRECT", "RULE-SET,bulk-classical,DIRECT",
                      "RULE-SET,core,AI", "DOMAIN-SUFFIX,fixed.example,Fixed", "AND,((NETWORK,udp)),X", "MATCH,Все остальное"],
        }

    def route(self, domain):
        return explain_route.explain(self.profile, domain, self.root)

    def test_first_matching_rule_wins(self):
        self.assertEqual(self.route("gemini.google.com")["target"], "AI")
        self.assertEqual(self.route("www.gstatic.com")["target"], "DIRECT")
        self.assertEqual(self.route("storage.googleapis.com")["target"], "DIRECT")
        self.assertEqual(self.route("anything.example")["target"], "Все остальное")

    def test_classical_keyword_regex_and_user_lists(self):
        self.assertEqual(self.route("alt3-mtalk.google.com")["target"], "DIRECT")  # keyword beats the google.com core rule
        self.assertEqual(self.route("cdn4.example.com")["target"], "DIRECT")
        self.assertEqual(self.route("a.mine.example")["index"], 0)

    def test_static_rules_and_ip_sets(self):
        self.assertEqual(self.route("x.fixed.example")["target"], "Fixed")  # the ipcidr set and the AND rule are skipped

    def test_unreadable_binary_sets_make_the_answer_uncertain(self):
        profile = dict(self.profile, rules=["RULE-SET,ru,DIRECT"] + self.profile["rules"])
        result = explain_route.explain(profile, "gemini.google.com", self.root)
        self.assertEqual(result["target"], "AI")
        self.assertEqual(result["uncertain"], ["ru"])


class Report(unittest.TestCase):
    OLD = {"domain": {"keep": {"domains": 10, "sha256": "a"}, "gone": {"domains": 5, "sha256": "b"}, "same": {"domains": 3, "sha256": "c"}, "edit": {"domains": 7, "sha256": "d"}},
           "ip": {"net": {"cidrs": 4, "sha256": "e"}}, "mirror": {}}
    NEW = {"domain": {"keep": {"domains": 12, "sha256": "a2"}, "new": {"domains": 2, "sha256": "n"}, "same": {"domains": 3, "sha256": "c"}, "edit": {"domains": 7, "sha256": "d2"}},
           "ip": {"net": {"cidrs": 4, "sha256": "e"}}, "mirror": {"ru-apps": {"bytes": 100, "sha256": "m"}}}

    def test_diff(self):
        rows = {(r["kind"], r["name"]): r for r in report.diff_manifests(self.OLD, self.NEW)}
        self.assertEqual(set(rows), {("domain", "keep"), ("domain", "gone"), ("domain", "new"), ("domain", "edit"), ("mirror", "ru-apps")})
        self.assertEqual(rows[("domain", "keep")]["status"], "changed")
        self.assertEqual(rows[("domain", "gone")]["status"], "removed")
        self.assertEqual(rows[("domain", "new")]["status"], "added")

    def test_markdown_and_commit_message(self):
        rows = report.diff_manifests(self.OLD, self.NEW)
        markdown = report.render_markdown(rows, {"itdog": "0123456789abcdef"})
        self.assertIn("| domain/keep | changed | 10 | 12 | +2 |", markdown)
        self.assertIn("| domain/edit | changed | 7 | 7 | content changed |", markdown)
        self.assertIn("`0123456789ab`", markdown)
        message = report.commit_message(rows)
        self.assertTrue(message.startswith("chore: update rulesets (5 sets changed)"))
        self.assertIn("- removed: domain/gone", message)

    def test_no_changes(self):
        self.assertEqual(report.commit_message([]), "chore: update profiles")
        self.assertIn("No ruleset changes.", report.render_markdown([]))

    def test_ls_remote_parsing(self):
        self.assertEqual(report.parse_ls_remote("0123456789abcdef0123\trefs/heads/main\n"), "0123456789abcdef0123")
        self.assertIsNone(report.parse_ls_remote(""))


class MihomoUpdate(unittest.TestCase):
    def test_versions(self):
        self.assertTrue(update_mihomo.is_newer("v1.19.31", "v1.19.30"))
        self.assertTrue(update_mihomo.is_newer("v1.20.0", "v1.19.99"))
        self.assertFalse(update_mihomo.is_newer("v1.19.30", "v1.19.30"))
        self.assertFalse(update_mihomo.is_newer("v1.9.0", "v1.19.0"))

    def test_asset_selection(self):
        release = {"assets": [{"name": "mihomo-linux-amd64-v1.20.0.gz"}, {"name": "mihomo-linux-amd64-compatible-v1.20.0.gz", "id": 2},
                              {"name": "mihomo-linux-amd64-compatible-v1.20.0.deb"}]}
        self.assertEqual(update_mihomo.pick_asset(release)["id"], 2)
        self.assertIsNone(update_mihomo.pick_asset({"assets": []}))

    def test_rewrite_keeps_everything_else(self):
        text = "mihomo:\n  version: v1.19.30\n  asset: old.gz\n  sha256: 00\n\nmalw:\n  version: untouched\n"
        out = update_mihomo.rewrite_build_yaml(text, "v1.20.0", "new.gz", "ff")
        data = yaml.safe_load(out)
        self.assertEqual(data["mihomo"], {"version": "v1.20.0", "asset": "new.gz", "sha256": "ff"})
        self.assertEqual(data["malw"]["version"], "untouched")

    def test_rewrite_of_the_committed_file(self):
        text = (REPO / "settings/build.yaml").read_text(encoding="utf-8")
        data = yaml.safe_load(update_mihomo.rewrite_build_yaml(text, "v9.9.9", "x.gz", "ab"))
        self.assertEqual(data["mihomo"]["version"], "v9.9.9")
        self.assertEqual(data["guard"], yaml.safe_load(text)["guard"])

    def test_missing_block_is_an_error(self):
        with self.assertRaises(RuntimeError):
            update_mihomo.rewrite_build_yaml("malw: {}\n", "v1", "a", "b")


if __name__ == "__main__":
    unittest.main()
