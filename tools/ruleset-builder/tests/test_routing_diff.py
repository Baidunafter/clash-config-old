"""Tests for routing_diff (effective target of every known domain, before vs after)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import routing_diff as rd  # noqa: E402


def make_tree(root: Path, sets: dict[str, list[str]], rules: dict, classical: dict[str, list[str]] | None = None) -> Path:
    (root / "settings").mkdir(parents=True)
    (root / "settings/rules.yaml").write_text(yaml.safe_dump(rules, allow_unicode=True), encoding="utf-8")
    (root / "generated/source/domain").mkdir(parents=True)
    for name, domains in sets.items():
        (root / "generated/source/domain" / f"{name}.txt").write_text("".join(f"+.{d}\n" for d in domains), encoding="utf-8")
    if classical:
        (root / "generated/classical").mkdir(parents=True)
        for name, payload in classical.items():
            (root / "generated/classical" / f"{name}-classical.yaml").write_text(yaml.safe_dump({"payload": payload}), encoding="utf-8")
    return root


class RoutingDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def tree(self, name, sets, rules, classical=None):
        return rd.Tree(make_tree(self.base / name, sets, rules, classical))

    RULES = {"generated_targets": {"a": "G1", "b": "G2"}, "generated_blocks": ["blk"],
             "ordered_rules": [{"domain": "a"}, {"domain": "b"}, "MATCH,Rest"]}

    def test_identical_trees_have_no_changes(self):
        sets = {"a": ["x.com"], "b": ["y.com"], "blk": []}
        before, after = self.tree("b", sets, self.RULES), self.tree("a", sets, self.RULES)
        self.assertEqual(rd.diff_trees(before, after), [])
        self.assertIn("No domain changes", rd.render([]))

    def test_rule_order_decides_the_target(self):
        sets = {"a": ["shared.com", "only-a.com"], "b": ["shared.com", "only-b.com"], "blk": []}
        swapped = dict(self.RULES, ordered_rules=[{"domain": "b"}, {"domain": "a"}, "MATCH,Rest"])
        changes = rd.diff_trees(self.tree("before", sets, self.RULES), self.tree("after", sets, swapped))
        self.assertEqual([(c["domain"], c["before"], c["after"]) for c in changes], [("shared.com", "G1", "G2")])

    def test_suffix_semantics_and_removed_category(self):
        before = self.tree("before", {"a": ["example.com"], "b": ["sub.example.com"], "blk": []}, self.RULES)
        self.assertEqual(before.route("deep.sub.example.com")[0], "G1")  # parent entry of the earlier rule wins
        after_rules = dict(self.RULES, ordered_rules=[{"domain": "b"}, "MATCH,Rest"])
        after = self.tree("after", {"b": ["sub.example.com"], "a": [], "blk": []}, after_rules)
        changes = rd.diff_trees(before, after)
        self.assertEqual({(c["domain"], c["before"], c["after"]) for c in changes},
                         {("example.com", "G1", "(MATCH)"), ("sub.example.com", "G1", "G2")})

    def test_blocks_are_reject_and_classical_companions_count(self):
        rules = {"generated_targets": {"a": "G1"}, "generated_blocks": ["blk"], "ordered_rules": [{"block": "blk"}, {"domain": "a"}, "MATCH,Rest"]}
        tree = self.tree("t", {"a": ["a.com"], "blk": ["ads.com"]}, rules, {"blk": ["DOMAIN-KEYWORD,tracker", "DOMAIN-REGEX,^cdn[0-9]\\.x\\.com$"]})
        self.assertEqual(tree.route("ads.com")[0], "REJECT")
        self.assertEqual(tree.route("my-tracker.net")[0], "REJECT")
        self.assertEqual(tree.route("cdn7.x.com")[0], "REJECT")
        self.assertEqual(tree.route("a.com")[0], "G1")
        self.assertEqual(tree.route("unknown.org")[0], "(MATCH)")

    def test_static_rules_participate_in_the_order(self):
        rules = {"generated_targets": {"a": "G1"}, "generated_blocks": [],
                 "ordered_rules": ["DOMAIN-SUFFIX,fixed.com,Fixed", {"domain": "a"}, "DOMAIN-KEYWORD,chrome,DIRECT", "MATCH,Rest"]}
        tree = self.tree("t", {"a": ["fixed.com", "a.com"]}, rules)
        self.assertEqual(tree.route("www.fixed.com"), ("Fixed", "static:fixed.com"))
        self.assertEqual(tree.route("a.com")[0], "G1")
        self.assertEqual(tree.route("chrome.example")[0], "DIRECT")
        self.assertIn("fixed.com", tree.universe)

    def test_report_groups_changes(self):
        changes = [{"domain": f"d{i}.com", "before": "REJECT", "after": "Twitch", "before_rule": "twitch-ads", "after_rule": "twitch-ads"} for i in range(3)]
        text = rd.render(changes, examples=2)
        self.assertIn("3 domain(s) change target:", text)
        self.assertIn("REJECT -> Twitch: 3", text)
        self.assertIn("... and 1 more", text)


if __name__ == "__main__":
    unittest.main()
