import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import knowledge

ROOT = Path(__file__).resolve().parents[1]


class ImportedSkillTests(unittest.TestCase):
    def test_cards_have_required_frontmatter(self):
        cards = sorted((ROOT / "skills" / "imported").glob("*/SKILL.md"))
        self.assertGreaterEqual(len(cards), 20)
        for card in cards:
            text = card.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---"), card)
            front = text.split("---", 2)[1]
            for key in ("name", "description", "source", "license", "ctf_domains", "status"):
                self.assertRegex(front, rf"(?m)^{key}\s*:", f"{card}: missing {key}")
            self.assertIn("http", front)

    def test_catalog_is_populated_and_marks_imports(self):
        catalog = knowledge.load_catalog(ROOT)
        self.assertGreaterEqual(catalog.get("total", 0), 2000)
        imported = [e for e in catalog["entries"] if e.get("status") == "imported"]
        self.assertGreaterEqual(len(imported), 20)

    def test_source_verified_recipes_are_opt_in(self):
        hits = knowledge.retrieve("libfuzzer coverage crash", ROOT / "recipes",
                                  include_source_verified=False, top_k=10)
        self.assertFalse(any(h.get("id") == "imported-libfuzzer" for h in hits))
        hits = knowledge.retrieve("libfuzzer coverage crash", ROOT / "recipes",
                                  include_source_verified=True, top_k=10)
        self.assertTrue(any(h.get("id") == "imported-libfuzzer" for h in hits))

    def test_catalog_search_finds_memory_forensics(self):
        hits = knowledge.search_catalog("volatility memory forensics", ROOT, top_k=5)
        self.assertTrue(hits)
        blob = " ".join(f"{h.get('name')} {h.get('description')}" for h in hits).lower()
        self.assertIn("volatility", blob)

    def test_recipe_audit_accepts_source_verified(self):
        self.assertEqual(knowledge.audit(ROOT / "recipes"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
