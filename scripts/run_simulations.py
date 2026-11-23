"""AgentFence Attack Simulation Runner.

Initialises (and seeds, if empty) the database on its own, runs every attack
scenario against the real gateway pipeline and exits non-zero if any scenario
was not blocked for the expected reason. Suitable for CI.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.database.seed import seed_database  # noqa: E402
from app.database.session import get_db  # noqa: E402
from app.simulations.engine import attack_simulation_lab  # noqa: E402


def main() -> int:
    seed_database()
    with get_db() as db:
        results = attack_simulation_lab.run_all_simulations(db)
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    print("=" * 70)
    print("AGENTFENCE ATTACK SIMULATION LAB - LIVE RUN")
    print("=" * 70)
    print(f"Executed: {total} attack scenarios | Passed: {passed}/{total}\n")
    for idx, r in enumerate(results, start=1):
        status = "PASSED [BLOCKED]" if r["passed"] else "FAILED [EXPLOITED]"
        print(f"[{idx}/{total}] {r['scenario_name']}")
        print(f"     Expected: {r['expected_result']}")
        print(f"     Actual:   {r['actual_result']}")
        print(f"     Status:   {status}\n")
    print("=" * 70)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
