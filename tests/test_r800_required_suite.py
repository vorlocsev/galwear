import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_run_required_suite import run_required

class RequiredSuiteTests(unittest.TestCase):
    def run_case(self, behavior):
        class Fixture(unittest.TestCase):
            def test_example(self):
                behavior(self)
        suite = unittest.TestSuite([Fixture("test_example")])
        with patch("unittest.defaultTestLoader.discover", return_value=suite):
            return run_required(".", "fixture.py", unittest.TextTestRunner(stream=io.StringIO()))

    def test_success(self):
        self.assertEqual(self.run_case(lambda _: None), 0)

    def test_empty(self):
        with patch("unittest.defaultTestLoader.discover", return_value=unittest.TestSuite()):
            self.assertEqual(run_required(".", "missing.py"), 1)

    def test_skip(self):
        self.assertEqual(self.run_case(lambda case: case.skipTest("missing prerequisite")), 1)

    def test_failure(self):
        self.assertEqual(self.run_case(lambda case: case.fail("regression")), 1)

    def test_expected_failure(self):
        class Fixture(unittest.TestCase):
            @unittest.expectedFailure
            def test_example(self):
                self.fail("known regression")
        suite = unittest.TestSuite([Fixture("test_example")])
        with patch("unittest.defaultTestLoader.discover", return_value=suite):
            self.assertEqual(run_required(".", "fixture.py", unittest.TextTestRunner(stream=io.StringIO())), 1)

if __name__ == "__main__":
    unittest.main()
