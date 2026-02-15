import argparse
import json
from collections import Counter
from pathlib import Path


def load_findings(path):
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(payload, dict):
        if isinstance(payload.get("findings"), list):
            return payload["findings"]
    if isinstance(payload, list):
        return payload
    raise ValueError(f"Unsupported report format: {path}")


def counts_by_rule(items):
    counter = Counter()
    for item in items:
        if isinstance(item, dict):
            counter[str(item.get("rule_id", "unknown"))] += 1
    return counter


def main():
    parser = argparse.ArgumentParser(description="Compare rule hit deltas between two findings/queue JSON files.")
    parser.add_argument("--before", required=True, help="Path to 'before' findings JSON or queue JSON")
    parser.add_argument("--after", required=True, help="Path to 'after' findings JSON or queue JSON")
    parser.add_argument("--top", type=int, default=30, help="Max changed rules to print")
    args = parser.parse_args()

    before_items = load_findings(args.before)
    after_items = load_findings(args.after)
    before = counts_by_rule(before_items)
    after = counts_by_rule(after_items)
    changed = []
    for rid in sorted(set(before) | set(after)):
        b = int(before.get(rid, 0))
        a = int(after.get(rid, 0))
        if a != b:
            changed.append((rid, b, a, a - b))
    changed.sort(key=lambda row: (-abs(row[3]), row[0]))

    print(f"before_total={len(before_items)}")
    print(f"after_total={len(after_items)}")
    print(f"changed_rules={len(changed)}")
    print("rule_id\tbefore\tafter\tdelta")
    for rid, b, a, d in changed[: max(1, int(args.top))]:
        print(f"{rid}\t{b}\t{a}\t{d:+d}")


if __name__ == "__main__":
    main()
