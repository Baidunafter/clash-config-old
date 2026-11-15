"""Tests for the WARP proxy renderer (tools/config-builder/warp_proxies.py)."""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "config-builder"))

import warp_proxies as w  # noqa: E402
import yaml  # noqa: E402

REPO = HERE.parents[2]


def write_sources(root: Path) -> None:
    (root / "geo-endpoint.yaml").write_text('proxies:\n  - name: "[🌍] NL"\n    server: nl.example\n    port: 4500\n', encoding="utf-8")
    origin = "".join(f'  - name: "[⭐] h{i}:4500"\n    server: h{i}\n    port: 4500\n' for i in range(5))
    (root / "origin-endpoint.yaml").write_text("proxies:\n" + origin, encoding="utf-8")
    (root / "default-endpoint.yaml").write_text('proxies:\n  - name: "10.0.0.1:500"\n    server: 10.0.0.1\n    port: 500\n', encoding="utf-8")
    (root / "masque-endpoint.yaml").write_text(
        'proxies:\n  - name: "[🎭] Q"\n    server: 1.1.1.1\n    port: 443\n  - name: "[🎭] H2"\n    server: 1.1.1.1\n    port: 443\n    network: h2\n',
        encoding="utf-8")


AMNEZIA = {"base": {"jc": 4}, "default": {"i1": "<b 0x01>"}, "alt1": {"i1": "<b 0x02>"},
           "alt2": {"i1": "<b 0x03>"}, "alt3": {"i1": "<b 0x04>", "i2": "<b 0x05>"}}


class Rendering(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        write_sources(self.dir)

    def test_types_are_rendered_in_canonical_order_and_selectable(self):
        text = w.render_warp(self.dir, ["masque", "geo"], AMNEZIA)
        self.assertLess(text.index("geo-endpoint"), text.index("masque"))
        self.assertNotIn("origin-endpoint", text)
        self.assertNotIn("10.0.0.1", text)

    def test_default_nodes_get_marker_and_masque_uses_its_anchor(self):
        text = w.render_warp(self.dir, ["default", "masque"], AMNEZIA)
        self.assertIn('name: "[☁️] 10.0.0.1:500"', text)
        self.assertIn("<<: *warp-masque", text)
        self.assertIn("network: h2", text)

    def test_first_three_4500_origin_nodes_get_alt_variants(self):
        text = w.render_warp(self.dir, ["origin"], AMNEZIA)
        self.assertEqual(text.count("(Alt "), 3)
        self.assertIn('"[⭐] (Alt 1) h0:4500"', text)
        self.assertIn("i2: *i2-alt3", text)
        self.assertEqual(text.count("i2: *i2-"), 1)

    def test_rendered_block_is_valid_yaml_with_unique_names(self):
        body = "warp-common: &warp-common {type: wireguard}\nwarp-masque: &warp-masque {type: masque}\n" \
               "amnezia-base: &amnezia-base {jc: 4}\ni1-alt1: &i1-alt1 x\ni1-alt2: &i1-alt2 y\ni1-alt3: &i1-alt3 z\ni2-alt3: &i2-alt3 q\n" \
               "proxies:\n" + w.render_warp(self.dir, list(w.TYPES), AMNEZIA) + "\n"
        data = yaml.safe_load(body)
        names = [p["name"] for p in data["proxies"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), 1 + 5 + 3 + 1 + 2)

    def test_anchor_rendering(self):
        text = w.render_amnezia_anchors(AMNEZIA)
        self.assertIn("amnezia-common: &amnezia-common\n  jc: 4", text)
        self.assertIn("i2-alt3: &i2-alt3 <b 0x05>", text)

    def test_unknown_or_empty_types_fail(self):
        with self.assertRaises(RuntimeError):
            w.render_warp(self.dir, ["geo", "nope"], AMNEZIA)
        with self.assertRaises(RuntimeError):
            w.validate_types([])


class MasqueNodes(unittest.TestCase):
    """`[🌍 MQ]` nodes (QUIC, port 443) inherit warp-masque, the others warp-common."""

    def test_node_anchor_is_chosen_by_the_mq_token_of_the_marker(self):
        self.assertEqual(w.node_anchor("geo", "[🌍 MQ] 🇳🇱 Нидерланды"), "warp-masque")
        self.assertEqual(w.node_anchor("geo", "[🌍 MQ] TEL 🇵🇱 Польша"), "warp-masque")
        self.assertEqual(w.node_anchor("origin", "[⭐ MQ] x"), "warp-masque")  # any endpoint file
        self.assertEqual(w.node_anchor("geo", "[🌍] 🇳🇱 Нидерланды"), "warp-common")
        self.assertEqual(w.node_anchor("geo", "[🌍] 🇳🇱 MQ-city"), "warp-common")  # MQ outside the marker is just text
        self.assertEqual(w.node_anchor("geo", "🇳🇱 plain"), "warp-common")
        self.assertEqual(w.node_anchor("masque", "[🎭] WARP-MASQUE QUIC"), "warp-masque")

    def render(self, geo_yaml):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_sources(root)
            (root / "geo-endpoint.yaml").write_text(geo_yaml, encoding="utf-8")
            body = ("warp-common: &warp-common {type: wireguard}\nwarp-masque: &warp-masque {type: masque}\n"
                    "amnezia-base: &amnezia-base {jc: 4}\ni1-alt1: &i1-alt1 x\ni1-alt2: &i1-alt2 y\ni1-alt3: &i1-alt3 z\ni2-alt3: &i2-alt3 q\n"
                    "proxies:\n" + w.render_warp(root, ["geo"], AMNEZIA) + "\n")
            return {p["name"]: p for p in yaml.safe_load(body)["proxies"]}

    def test_mq_nodes_render_as_masque_and_wireguard_nodes_stay_wireguard(self):
        nodes = self.render('proxies:\n'
                            '  - name: "[🌍] 🇳🇱 Нидерланды"\n    server: nl.example\n    port: 4500\n'
                            '  - name: "[🌍 MQ] 🇳🇱 Нидерланды"\n    server: nl.example\n    port: 443\n')
        wg, mq = nodes["[🌍] 🇳🇱 Нидерланды"], nodes["[🌍 MQ] 🇳🇱 Нидерланды"]
        self.assertEqual((wg["type"], wg["port"]), ("wireguard", 4500))
        self.assertEqual((mq["type"], mq["port"], mq["server"]), ("masque", 443, "nl.example"))

    def test_the_text_of_an_mq_node_uses_the_masque_merge_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_sources(root)
            (root / "geo-endpoint.yaml").write_text('proxies:\n  - name: "[🌍 MQ] X"\n    server: x.example\n    port: 443\n', encoding="utf-8")
            text = w.render_warp(root, ["geo"], AMNEZIA)
        self.assertIn('  - name: "[🌍 MQ] X"\n    <<: *warp-masque\n    server: x.example\n    port: 443', text)
        self.assertNotIn("*warp-common", text)

    def test_an_mq_node_in_the_first_origin_slots_never_gets_wireguard_obfuscation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_sources(root)
            (root / "origin-endpoint.yaml").write_text('proxies:\n  - name: "[⭐ MQ] a:4500"\n    server: a\n    port: 4500\n', encoding="utf-8")
            text = w.render_warp(root, ["origin"], AMNEZIA)
        self.assertNotIn("amnezia-wg-option", text)
        self.assertNotIn("(Alt", text)

    def test_committed_geo_file_pairs_every_mq_node_with_a_wireguard_node(self):
        nodes = w.load_nodes(REPO / "proxies", "geo")
        mq = [n for n in nodes if w.node_anchor("geo", str(n["name"])) == "warp-masque"]
        wg = [n for n in nodes if n not in mq]
        self.assertGreaterEqual(len(mq), 10)
        for node in mq:
            self.assertEqual(node["port"], 443, node["name"])
            self.assertIn(node["server"], {n["server"] for n in wg}, f"{node['name']} has no WireGuard twin")
        self.assertTrue(all(str(n["name"]).startswith("[🌍") for n in nodes))

    def test_auto_select_group_takes_the_mq_nodes_but_never_the_limited_ones(self):
        template = yaml.safe_load((REPO / "templates/profile.yaml").read_text(encoding="utf-8"))
        group = {g["name"]: g for g in template["proxy-groups"]}["🌍 Авто"]
        include, exclude = re.compile(group["filter"]), re.compile(group["exclude-filter"])
        names = [str(n["name"]) for n in w.load_nodes(REPO / "proxies", "geo")]
        picked = [n for n in names if include.search(n) and not exclude.search(n)]
        self.assertIn("[🌍 MQ] 🇳🇱 Нидерланды", picked)
        self.assertIn("[🌍] 🇳🇱 Нидерланды", picked)
        self.assertFalse([n for n in picked if "TEL" in n])
        self.assertEqual(len(picked), len(names) - 6)  # three TEL locations x two protocols


class GeminiCopies(unittest.TestCase):
    DNS = "https://xbox.example/dns-query"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        write_sources(self.root)
        (self.root / "geo-endpoint.yaml").write_text(
            'proxies:\n  - name: "[🌍] 🇳🇱 Нидерланды"\n    server: nl.example\n    port: 4500\n'
            '  - name: "[🌍 MQ] 🇳🇱 Нидерланды"\n    server: nl.example\n    port: 443\n', encoding="utf-8")

    def nodes(self, text):
        body = ("warp-common: &warp-common {type: wireguard, dns: [main]}\nwarp-masque: &warp-masque {type: masque, dns: [main]}\n"
                "amnezia-base: &amnezia-base {jc: 4}\ni1-alt1: &i1-alt1 x\ni1-alt2: &i1-alt2 y\ni1-alt3: &i1-alt3 z\ni2-alt3: &i2-alt3 q\n"
                "proxies:\n" + text + "\n")
        return {p["name"]: p for p in yaml.safe_load(body)["proxies"]}

    def test_clone_names(self):
        self.assertEqual(w.clone_name("[🌍] 🇳🇱 Нидерланды"), "[GM] 🇳🇱 Нидерланды")
        self.assertEqual(w.clone_name("[🌍 MQ] TEL 🇵🇱 Польша"), "[GM MQ] TEL 🇵🇱 Польша")
        self.assertEqual(w.clone_name("[⭐] FRA #1:4500"), "[GM] FRA #1:4500")
        self.assertEqual(w.clone_name("162.159.195.10:500"), "[GM] 162.159.195.10:500")

    def test_every_node_gets_a_copy_with_its_own_dns_and_the_same_anchor(self):
        nodes = self.nodes(w.render_warp(self.root, ["geo", "masque"], AMNEZIA, clone_dns=self.DNS))
        self.assertEqual(nodes["[🌍] 🇳🇱 Нидерланды"]["dns"], ["main"])  # the originals keep the main resolvers
        copy_wg, copy_mq = nodes["[GM] 🇳🇱 Нидерланды"], nodes["[GM MQ] 🇳🇱 Нидерланды"]
        self.assertEqual((copy_wg["type"], copy_wg["port"], copy_wg["dns"]), ("wireguard", 4500, [self.DNS]))
        self.assertEqual((copy_mq["type"], copy_mq["port"], copy_mq["dns"]), ("masque", 443, [self.DNS]))
        self.assertEqual(copy_wg["server"], "nl.example")
        for copied in ("[GM] Q", "[GM] H2"):  # the Cloudflare masque nodes are copied too
            self.assertEqual((nodes[copied]["type"], nodes[copied]["dns"]), ("masque", [self.DNS]))
        names = list(nodes)
        self.assertEqual(len(names), len(set(names)))

    def test_text_of_a_copy(self):
        text = w.render_warp(self.root, ["geo"], AMNEZIA, clone_dns=self.DNS)
        self.assertIn('  - name: "[GM] 🇳🇱 Нидерланды"\n    <<: *warp-common\n    server: nl.example\n    port: 4500\n    dns:\n      - https://xbox.example/dns-query', text)

    def test_without_clone_dns_nothing_is_added(self):
        self.assertNotIn("GM", w.render_warp(self.root, ["geo", "masque"], AMNEZIA))

    def test_copies_get_no_obfuscation_variants(self):
        text = w.render_warp(self.root, ["origin"], AMNEZIA, clone_dns=self.DNS)
        self.assertEqual(text.count("(Alt "), 3)  # only the originals
        self.assertEqual(text.count("amnezia-wg-option"), 3)


class FilterPruning(unittest.TestCase):
    TEXT = (
        '  - name: A\n    filter: "⭐|☁️|🎭"\n'
        '  - name: B\n    filter: "🌍|⭐|☁️|🎭"\n'
        "  - name: C\n    filter: '^\\\\[🌍\\\\]'\n"
        '  - name: D\n    filter: "☁️"\n'
    )

    def test_unused_markers_are_removed(self):
        text = self.TEXT.replace('  - name: D\n    filter: "☁️"\n', "")
        out = w.prune_filters(text, ["geo", "origin", "masque"])
        self.assertIn('filter: "⭐|🎭"', out)
        self.assertIn('filter: "🌍|⭐|🎭"', out)
        self.assertNotIn("☁", out)
        self.assertIn("^\\\\[🌍\\\\]", out)  # regex filters are left alone

    def test_all_types_keep_text_unchanged(self):
        text = self.TEXT.replace('  - name: D\n    filter: "☁️"\n', "")
        self.assertEqual(w.prune_filters(text, list(w.TYPES)), text)

    def test_filter_that_would_become_empty_is_an_error(self):
        with self.assertRaises(RuntimeError):
            w.prune_filters(self.TEXT, ["geo", "origin", "masque"])


class ProxyChecks(unittest.TestCase):
    def test_duplicate_names_fail(self):
        with self.assertRaises(RuntimeError):
            w.check_proxies({"proxies": [{"name": "x"}, {"name": "x"}]}, "p.yaml")

    def test_filter_without_match_is_a_warning(self):
        profile = {"proxies": [{"name": "[🌍] a"}], "proxy-groups": [{"name": "G", "filter": "⭐"}, {"name": "H", "filter": "🌍"}]}
        warnings = w.check_proxies(profile, "p.yaml")
        self.assertEqual(len(warnings), 1)
        self.assertIn("'G'", warnings[0])

    def test_invalid_regex_fails(self):
        with self.assertRaises(RuntimeError):
            w.check_proxies({"proxies": [], "proxy-groups": [{"name": "G", "filter": "("}]}, "p.yaml")


ACCOUNT = {
    "wireguard": {"ip": "172.16.0.2", "ipv6": "2606:4700:110:8e80:88b7:6faa:1bd1:91e6", "private-key": "PRIV=", "public-key": "PUB=",
                  "reserved": [1, 2, 3], "mtu": 1280},
    "masque": {"sni": "example.org", "ip": "172.16.0.2", "ipv6": "2606:4700:110:81ac::1", "private-key": "MPRIV=", "public-key": "MPUB="},
}


class WarpAnchors(unittest.TestCase):
    def render(self, dns=("https://dns.example/dns-query",)):
        text = w.render_warp_anchors(ACCOUNT, list(dns))
        # The anchors reference the amnezia anchors, which live in another block.
        return yaml.safe_load("amnezia-common: &amnezia-common {jc: 4}\ni1-default: &i1-default x\n" + text)

    def test_wireguard_anchor(self):
        data = self.render()["warp-common"]
        self.assertEqual(data["type"], "wireguard")
        self.assertEqual(data["ipv6"], "2606:4700:110:8e80:88b7:6faa:1bd1:91e6")  # stays a string
        self.assertEqual(data["reserved"], [1, 2, 3])
        self.assertEqual(data["dns"], ["https://dns.example/dns-query"])
        self.assertEqual(data["amnezia-wg-option"]["i1"], "x")

    def test_masque_anchor(self):
        data = self.render()["warp-masque"]
        self.assertEqual((data["type"], data["sni"], data["private-key"]), ("masque", "example.org", "MPRIV="))
        self.assertEqual(data["dns"], ["https://dns.example/dns-query"])

    def test_single_dns_value_is_used_everywhere(self):
        data = self.render(dns=["https://a.example/dns-query"])
        self.assertEqual(data["warp-common"]["dns"], data["warp-masque"]["dns"])

    def test_env_overrides_private_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "acc.yaml"
            path.write_text(yaml.safe_dump(ACCOUNT), encoding="utf-8")
            account = w.load_warp_account(path, environ={"WARP_WG_PRIVATE_KEY": " NEW= "})
            self.assertEqual(account["wireguard"]["private-key"], "NEW=")
            self.assertEqual(account["masque"]["private-key"], "MPRIV=")

    def test_missing_credentials_fail(self):
        bad = {"wireguard": dict(ACCOUNT["wireguard"], **{"private-key": ""}), "masque": ACCOUNT["masque"]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "acc.yaml"
            path.write_text(yaml.safe_dump(bad), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                w.load_warp_account(path, environ={})


class RepositorySources(unittest.TestCase):
    """The committed proxies/*.yaml must render without duplicate names."""

    def test_committed_sources_render(self):
        amnezia = w.load_amnezia(REPO / "settings/amnezia.yaml")
        self.assertIn("alt3", amnezia)
        text = w.render_warp(REPO / "proxies", list(w.TYPES), amnezia)
        names = [line.split("name: ", 1)[1] for line in text.splitlines() if "- name:" in line]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreater(len(names), 30)


if __name__ == "__main__":
    unittest.main()
