"""AgentFence audit ledger CLI.

    python scripts/audit_cli.py verify                 # verify the live v2 hash chain
    python scripts/audit_cli.py verify-legacy <file>   # verify an archived pre-2.0 (v1) database
    python scripts/audit_cli.py export [tenant_id]     # print the ledger as JSON Lines

Pre-2.0 databases used an 11-field hash. On first start in dev mode the
gateway moves such a database aside (``agentfence.db.v1-<timestamp>.bak``)
instead of re-chaining it, so the original evidence is preserved unchanged and
can still be verified with ``verify-legacy``.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.audit.service import audit_service  # noqa: E402


def main(argv) -> int:
    if not argv or argv[0] not in ("verify", "verify-legacy", "export"):
        print(__doc__)
        return 2
    if argv[0] == "verify-legacy":
        if len(argv) != 2:
            print("usage: audit_cli.py verify-legacy <path-to-archived-db>")
            return 2
        ok, count, err = audit_service.verify_legacy_sqlite_chain(argv[1])
        print(f"legacy chain valid={ok} records={count} error={err}")
        return 0 if ok else 1

    from app.database.session import get_db, init_db
    init_db()
    with get_db() as db:
        if argv[0] == "verify":
            ok, count, err = audit_service.verify_audit_chain_integrity(db)
            print(f"chain valid={ok} records={count} error={err}")
            return 0 if ok else 1
        for line in audit_service.export_jsonl(db, argv[1] if len(argv) > 1 else None):
            sys.stdout.write(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
