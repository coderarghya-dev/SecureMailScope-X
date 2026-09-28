"""
SecureMailScope X - Fast Test Suite Runner
Runs each test module in backend/tests and collects comprehensive pass/fail statistics.
"""

import os
import sys
import unittest
import importlib

BACKEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

TESTS_DIR = os.path.join(BACKEND_DIR, "tests")
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

def run_suite():
    loader = unittest.TestLoader()
    test_files = [
        f[:-3] for f in sorted(os.listdir(TESTS_DIR))
        if f.startswith("test_") and f.endswith(".py")
    ]

    total_tests = 0
    total_failures = 0
    total_errors = 0
    total_skipped = 0

    print("================================================================================", flush=True)
    print(f"RUNNING SECUREMAILSCOPE X TEST SUITE ({len(test_files)} Modules)", flush=True)
    print("================================================================================", flush=True)

    for mod_name in test_files:
        try:
            mod = importlib.import_module(mod_name)
            suite = loader.loadTestsFromModule(mod)
            runner = unittest.TextTestRunner(verbosity=0)
            res = runner.run(suite)

            runs = res.testsRun
            fails = len(res.failures)
            errs = len(res.errors)
            skips = len(res.skipped)

            total_tests += runs
            total_failures += fails
            total_errors += errs
            total_skipped += skips

            status = "PASS" if (fails == 0 and errs == 0) else "FAIL"
            print(f"[{status}] {mod_name:<35} | {runs:>3} tests | {fails} fails | {errs} errs | {skips} skips", flush=True)
            if fails > 0 or errs > 0:
                for f in res.failures:
                    print(f"    FAIL: {f[0]}: {f[1]}", flush=True)
                for e in res.errors:
                    print(f"    ERROR: {e[0]}: {e[1]}", flush=True)
        except Exception as ex:
            print(f"[ERROR] {mod_name:<35} | Failed to load: {ex}", flush=True)

    print("================================================================================", flush=True)
    print(f"TOTAL: {total_tests} Tests Run | {total_failures} Failures | {total_errors} Errors | {total_skipped} Skipped", flush=True)
    print("================================================================================", flush=True)
    return total_failures == 0 and total_errors == 0

if __name__ == "__main__":
    success = run_suite()
    sys.exit(0 if success else 1)
