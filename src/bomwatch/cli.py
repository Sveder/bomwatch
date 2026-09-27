"""Command line entry point."""

import argparse
import json
import os
import sys
from collections import Counter

from bomwatch import __version__, collectors, diff, snapshot
from bomwatch.model import FAILED, OK

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_CHANGES = 3


def collector_list(text):
    """Parse ``--only``: a comma separated list of known collector names."""
    names = text.split(",")
    unknown = set(names) - set(collectors.COLLECTORS)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown collector: {', '.join(sorted(unknown))}"
        )
    return names


def build_parser():
    """Return the argument parser for the ``bomwatch`` command."""
    parser = argparse.ArgumentParser(
        prog="bomwatch",
        description="Software bill of materials and install watch.",
    )
    parser.add_argument(
        "--version", action="version", version=f"bomwatch {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="list installed software and save a snapshot")
    scan.add_argument(
        "--root",
        action="append",
        help="directory to search for envs; repeat for more, replaces the home default",
    )
    scan.add_argument(
        "--only", type=collector_list, help="comma separated collectors, e.g. dpkg,pip"
    )
    scan.add_argument("--state-dir", help="where snapshots are kept")
    scan.add_argument("--no-save", action="store_true", help="do not save a snapshot")
    scan.add_argument("--json", action="store_true", help="print JSON")
    scan.set_defaults(func=cmd_scan)

    changes = sub.add_parser("diff", help="compare two snapshots")
    changes.add_argument("files", nargs="*", metavar="FILE", help="OLD NEW snapshots")
    changes.add_argument("--state-dir", help="where snapshots are kept")
    changes.add_argument("--json", action="store_true", help="print JSON")
    changes.set_defaults(func=cmd_diff)
    return parser


def count_by_ecosystem(packages):
    """Return ``{ecosystem: count}`` for package dicts, sorted by ecosystem."""
    return dict(sorted(Counter(p["ecosystem"] for p in packages).items()))


def cmd_scan(args):
    """Scan the machine, save the snapshot and print a summary."""
    roots = collectors.resolve_roots(args.root)
    snap = snapshot.make(*collectors.collect_all(roots, args.only), roots=roots)
    failed = [n for n, s in snap["collectors"].items() if s == FAILED]
    if failed:
        print(f"collector failed: {', '.join(failed)}", file=sys.stderr)
    path = None
    if not args.no_save:
        path = snapshot.save(snap, snapshot.state_dir(args.state_dir))
    print_scan(snap, path, args.json)
    return EXIT_OK


def print_scan(snap, path, as_json):
    """Print the package counts of ``snap`` and where it was saved."""
    counts = count_by_ecosystem(snap["packages"])
    if as_json:
        result = {
            "snapshot": str(path) if path else None,
            "counts": counts,
            "collectors": snap["collectors"],
        }
        print(json.dumps(result, sort_keys=True))
        return
    for ecosystem, count in counts.items():
        print(f"{ecosystem:10} {count}")
    print(f"{'total':10} {len(snap['packages'])}")
    if path:
        print(f"saved {path}")


def load_pair(args):
    """Return the (old, new) snapshots to compare, or None if only one exists.

    With no FILE arguments the old side is the baseline of every older scan.
    """
    if args.files:
        return tuple(snapshot.load(p) for p in args.files)
    files = snapshot.history(snapshot.state_dir(args.state_dir))
    if len(files) < 2:
        return None
    new = snapshot.load(files[-1])
    names = set(collectors.COLLECTORS) | set(new["collectors"])
    wanted = [n for n in names if new["collectors"].get(n, OK) == OK]
    old = snapshot.baseline(files[:-1], wanted, new["roots"], collectors.USES_ROOTS)
    return old, new


def compare_pair(old, new):
    """Return ``(changes, not_compared)`` for two snapshots."""
    skipped = {
        **diff.roots_differ(old["roots"], new["roots"], collectors.USES_ROOTS),
        **diff.not_compared(old["collectors"], new["collectors"]),
    }
    return diff.compare(old["packages"], new["packages"], skip=skipped), skipped


def diff_json(changes, skipped, **extra):
    """Return the JSON text of a diff result."""
    result = {**extra, **diff.to_dict(changes), "not_compared": skipped}
    return json.dumps(result, sort_keys=True)


def cmd_diff(args):
    """Print the changes between two snapshots."""
    if len(args.files) not in (0, 2):
        print("diff takes no file or exactly two files", file=sys.stderr)
        return EXIT_USAGE
    pair = load_pair(args)
    if pair is None:
        if args.json:
            print(diff_json(diff.compare([], []), {}, first_scan=True))
        else:
            print("first scan, nothing to compare")
        return EXIT_OK
    changes, skipped = compare_pair(*pair)
    if args.json:
        print(diff_json(changes, skipped))
    else:
        print("\n".join(diff.to_lines(changes)) or "no changes")
        for name, reason in skipped.items():
            print(f"note: {name} not compared ({reason})")
    return EXIT_OK if diff.is_empty(changes) else EXIT_CHANGES


def main(argv=None):
    """Run the command line interface and return an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        return args.func(args)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except (OSError, ValueError) as exc:
        print(f"bomwatch: {exc}", file=sys.stderr)
        return EXIT_ERROR
