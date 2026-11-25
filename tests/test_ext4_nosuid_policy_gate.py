"""Static nosuid policy query contracts, using mocked SETools output."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_ext4_nosuid_policy_gate as a

class NosuidTests(unittest.TestCase):
    def evaluate(self,profile="stock",cap=True,bounds=(),denied=(),conditional=False):
        def query(tool,policy,*args):
            if "--polcap" in args:
                return ["policycap nnp_nosuid_transition;"] if cap else []
            if "--typebounds" in args:
                return list(bounds)
            source=args[args.index("-s")+1]
            target=args[args.index("-t")+1]
            klass=args[args.index("-c")+1]
            if "--type_transition" in args:
                default=args[args.index("-D")+1]
                return [f"type_transition {source} {target}:process {default};"]
            perm=args[args.index("-p")+1]
            if (source,target,perm) in denied:
                return []
            suffix=" [ flag ]:True" if conditional and perm=="nosuid_transition" else ""
            return [f"allow {source} {target}:{klass} {{ {perm} }};"+suffix]
        with patch.object(a,"query",side_effect=query):
            return a.evaluate(Path("policy"),profile)

    def test_direct_permission_route(self):
        result=self.evaluate()
        self.assertEqual(result["status"],a.READY)
        self.assertTrue(result["transitions"][0]["nosuid_permission_route"])
        self.assertFalse(result["runtime_transition_tested"])
        self.assertFalse(result["safe_to_flash"])

    def test_no_cap_no_bounds(self):
        result=self.evaluate(cap=False)
        self.assertEqual(result["status"],a.BLOCKED)
        self.assertIsNone(result["transitions"][0]["nosuid_permission"])

    def test_bounds_route_without_capability(self):
        result=self.evaluate(cap=False,bounds=["typebounds kernel intermediate;","typebounds intermediate init;"])
        self.assertEqual(result["status"],a.READY)
        self.assertEqual(result["transitions"][0]["typebounds_ancestry"],["init","intermediate","kernel"])
        self.assertTrue(result["transitions"][0]["typebounds_route"])

    def test_conditional_permission_not_accepted(self):
        self.assertEqual(self.evaluate(conditional=True)["status"],a.BLOCKED)

    def test_ordinary_permission_still_required(self):
        result=self.evaluate(denied=[("init","init_exec","entrypoint")])
        self.assertEqual(result["status"],a.BLOCKED)
        self.assertIn("init init_exec:file entrypoint",result["transitions"][0]["missing_static_prerequisites"])

    def test_fixture_requires_both_transitions(self):
        result=self.evaluate("fixture",denied=[("init","galwear_property_client","nosuid_transition")])
        self.assertEqual(result["status"],a.BLOCKED)
        self.assertEqual(len(result["transitions"]),2)
        self.assertEqual(result["transitions"][0]["missing_static_prerequisites"],[])
        self.assertTrue(result["transitions"][1]["missing_static_prerequisites"])

    def test_cycle_and_duplicate_bounds_rejected(self):
        for rows in (["typebounds init kernel;","typebounds kernel init;"],
                     ["typebounds kernel init;","typebounds other init;"]):
            with self.assertRaises(ValueError):
                a.bounds_ancestry(rows,"kernel","init")

    def test_unrelated_permission_rejected(self):
        with patch.object(a,"query",return_value=["allow kernel init:process2 nnp_transition;"]):
            self.assertFalse(a.allow(Path("policy"),"sesearch","kernel","init","process2",
                                     "nosuid_transition")["unconditional_allow_found"])

if __name__=="__main__":
    unittest.main()
