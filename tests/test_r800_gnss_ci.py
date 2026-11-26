"""Synthetic GitHub API metadata, no network or job creation."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gnss_ci as ci
import r800_gnss_readiness as readiness

SHA="a"*40


class CiTests(unittest.TestCase):
    def setUp(self):
        self.runs=[dict(path=path,id=100+i,run_attempt=1,head_sha=SHA,
                        event="push",repository={"full_name":ci.REPO},
                        head_repository={"full_name":ci.REPO},status="completed",
                        conclusion="success") for i,path in enumerate(ci.REQUIRED)]
        self.jobs=[dict(id=200+i,name=name,head_sha=SHA,run_id=100,run_attempt=1,
                        status="completed",conclusion="success",
                        steps=[dict(name=s,status="completed",conclusion="success")
                               for s in steps]) for i,(name,steps) in enumerate(ci.STEPS.items())]
        self.second=None
        self.calls=0

    def fetch(self,path):
        if "/jobs?" in path:
            self.assertIn("/100/attempts/1/jobs?",path)
            return {"total_count":len(self.jobs),"jobs":self.jobs},"b"*64
        self.calls+=1
        rows=self.second if self.calls==2 and self.second is not None else self.runs
        return {"total_count":len(rows),"workflow_runs":rows},"c"*64

    def run_check(self):
        return ci.check(SHA,self.fetch)

    def test_exact_head(self):
        result=self.run_check()
        self.assertEqual(result["status"],"CI_METADATA_PASS")
        self.assertEqual(len(result["workflows"]),7)
        self.assertFalse(result["ci_logs_verified"])
        self.assertFalse(result["safe_to_flash"])

    def test_missing_workflow(self):
        self.runs.pop()
        self.assertEqual(self.run_check()["status"],"REVIEW_REQUIRED")

    def test_newer_failed_run_blocks_old_success(self):
        newer=copy.deepcopy(self.runs[-1])
        newer.update(id=500,conclusion="failure")
        self.runs.append(newer)
        self.assertEqual(self.run_check()["status"],"REVIEW_REQUIRED")

    def test_wrong_sha(self):
        self.runs[0]["head_sha"]="d"*40
        with self.assertRaises(ValueError): self.run_check()

    def test_wrong_repository(self):
        self.runs[0]["head_repository"]["full_name"]="other/repo"
        with self.assertRaises(ValueError): self.run_check()

    def test_skipped_required_job(self):
        self.jobs[0]["conclusion"]="skipped"
        self.assertEqual(self.run_check()["status"],"REVIEW_REQUIRED")

    def test_skipped_step(self):
        self.jobs[0]["steps"][0]["conclusion"]="skipped"
        self.assertEqual(self.run_check()["status"],"REVIEW_REQUIRED")

    def test_missing_step(self):
        self.jobs[0]["steps"].pop()
        self.assertEqual(self.run_check()["status"],"REVIEW_REQUIRED")

    def test_duplicate_step(self):
        self.jobs[0]["steps"].append(self.jobs[0]["steps"][0])
        self.assertEqual(self.run_check()["status"],"REVIEW_REQUIRED")

    def test_wrong_attempt(self):
        self.jobs[0]["run_attempt"]=2
        with self.assertRaises(ValueError): self.run_check()

    def test_pagination_rejected(self):
        with self.assertRaises(ValueError):
            ci.collection({"total_count":101,"workflow_runs":self.runs},"workflow_runs")

    def test_selection_changed(self):
        self.second=copy.deepcopy(self.runs)
        self.second[-1]["run_attempt"]=2
        self.assertIn("CI_SELECTION_CHANGED",self.run_check()["problems"])

    def test_readiness_never_promotes_runtime(self):
        report=readiness.summarize(SHA,True,[readiness.outcome("exact_head_ci","PASS")])
        self.assertTrue(report["ci_verified"])
        self.assertFalse(report["ci_logs_verified"])
        self.assertFalse(report["safe_to_flash"])
        self.assertTrue(set(readiness.RUNTIME).issubset(report["blockers"]))


if __name__=="__main__":
    unittest.main()
