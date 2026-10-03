"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from bomwatch import (
    __version__,
    collectors,
    diff,
    export,
    history,
    snapshot,
    vulns,
)
from bomwatch.model import FAILED, OK, Package

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_CHANGES = 3
EXIT_VULNS = 4  # also: a new record is flagged or a credential (diff, audit)


def collector_list(text):
    """Parse ``--only``: a comma separated list of known collector names."""
    names = text.split(",")
    unknown = set(names) - set(collectors.COLLECTORS)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown collector: {', '.join(sorted(unknown))}"
        )
    return names


def positive(text):
    """Parse a whole number above zero."""
    try:
        number = int(text)
    except ValueError:
        number = 0
    if number < 1:
        raise argparse.ArgumentTypeError(f"not a positive number: {text}")
    return number


def build_parser():
    """Return the argument parser for the ``bomwatch`` command."""
    parser = argparse.ArgumentParser(
        prog="bomwatch",
        description="Software bill of materials and install watch.",
        epilog="collectors: " + ", ".join(collectors.COLLECTORS),
    )
    parser.add_argument(
        "--version", action="version", version=f"bomwatch {__version__}"
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state-dir", help="where snapshots are kept")
    common.add_argument(
        "-v", "--verbose", action="count", default=0, help="say more (-vv: debug)"
    )
    sub = parser.add_subparsers(dest="command")

    def command(name, func, text, json_flag=True):
        cmd = sub.add_parser(name, help=text, description=text, parents=[common])
        if json_flag:
            cmd.add_argument("--json", action="store_true", help="print JSON")
        cmd.set_defaults(func=func)
        return cmd

    def scan_options(cmd):
        cmd.add_argument(
            "--root",
            action="append",
            help="directory to search for envs and projects; repeat for more,"
            " replaces the home default",
        )
        cmd.add_argument(
            "--only",
            type=collector_list,
            help="comma separated collectors, e.g. dpkg,pip",
        )

    scan = command("scan", cmd_scan, "list installed software and save a snapshot")
    scan_options(scan)
    scan.add_argument("--no-save", action="store_true", help="do not save a snapshot")

    changes = command("diff", cmd_diff, "compare two snapshots")
    changes.add_argument("files", nargs="*", metavar="FILE", help="OLD NEW snapshots")
    changes.add_argument(
        "--vulns", action="store_true", help="look up new versions on osv.dev"
    )

    out = command("export", cmd_export, "write a snapshot as an SBOM", False)
    out.add_argument("file", nargs="?", metavar="FILE", help="snapshot, default newest")
    out.add_argument("--format", choices=export.FORMATS, default="cyclonedx")
    out.add_argument("-o", "--output", help="file to write, default stdout")

    audit = command("audit", cmd_audit, "list flagged records of a snapshot")
    audit.add_argument(
        "file", nargs="?", metavar="FILE", help="snapshot, default newest"
    )

    vuln = command("vulns", cmd_vulns, "look up known vulnerabilities on osv.dev")
    vuln.add_argument(
        "file", nargs="?", metavar="FILE", help="snapshot, default newest"
    )
    vuln.add_argument(
        "--no-details", action="store_true", help="ids only, no summaries"
    )

    log = command("log", cmd_log, "show when a package appeared and changed")
    log.add_argument("name", help="package name (any case)")
    log.add_argument("--ecosystem", help="only this ecosystem, e.g. pip")

    watch = command("watch", cmd_watch, "scan again and again, print what changes")
    scan_options(watch)
    watch.add_argument(
        "--interval", type=positive, default=300, help="seconds between scans"
    )
    watch.add_argument("--count", type=positive, help="stop after this many scans")
    watch.add_argument(
        "--vulns", action="store_true", help="look up new versions on osv.dev"
    )

    prune = command("prune", cmd_prune, "delete old snapshots", False)
    prune.add_argument("--keep", type=positive, required=True, help="how many to keep")
    prune.add_argument("--dry-run", action="store_true", help="only list them")
    return parser


def count_by_ecosystem(packages):
    """Return ``{ecosystem: count}`` for package dicts, sorted by ecosystem."""
    return dict(sorted(Counter(p["ecosystem"] for p in packages).items()))


def take_scan(args):
    """Run the collectors for ``args`` and return the new snapshot dict."""
    roots = collectors.resolve_roots(args.root)
    packages, status = collectors.collect_all(roots, args.only)
    snap = snapshot.make(packages, status, roots=roots)
    failed = [n for n, s in snap["collectors"].items() if s == FAILED]
    if failed:
        print(f"collector failed: {', '.join(failed)}", file=sys.stderr)
    return snap


def cmd_scan(args):
    """Scan the machine, save the snapshot and print a summary."""
    snap = take_scan(args)
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
        print(f"{ecosystem:12} {count}")
    print(f"{'total':12} {len(snap['packages'])}")
    if path:
        print(f"saved {path}")


def baseline_for(new, files):
    """Return the baseline of ``files`` (oldest first) for snapshot ``new``."""
    names = set(collectors.COLLECTORS) | set(new["collectors"])
    wanted = [n for n in names if snapshot.status(new, n) == OK]
    return snapshot.baseline(files, wanted, new["roots"], collectors.USES_ROOTS)


def load_pair(args):
    """Return the (old, new) snapshots to compare, or None if only one exists.

    With no FILE arguments the old side is the baseline of every older scan.
    Unreadable scans are skipped with a warning.
    """
    if args.files:
        return tuple(snapshot.load(p) for p in args.files)
    files = snapshot.history(snapshot.state_dir(args.state_dir))
    found = snapshot.latest(files)
    if found is None:
        return None
    index, new = found
    old = baseline_for(new, files[:index])
    return None if old is None else (old, new)


def compare_pair(old, new):
    """Return ``(changes, not_compared)`` for two snapshots."""
    names = set(old["collectors"]) | set(new["collectors"])
    uses_roots = [n for n in collectors.USES_ROOTS if n in names]
    skipped = {
        **diff.roots_differ(old["roots"], new["roots"], uses_roots),
        **diff.not_compared(
            {n: snapshot.status(old, n) for n in names},
            {n: snapshot.status(new, n) for n in names},
        ),
    }
    return diff.compare(old["packages"], new["packages"], skip=skipped), skipped


def diff_json(changes, skipped, **extra):
    """Return the JSON text of a diff result."""
    result = {**extra, **diff.to_dict(changes), "not_compared": skipped}
    return json.dumps(result, sort_keys=True)


def check_vulns(packages, system, details=True):
    """Return ``(found, summaries)`` from osv.dev for ``packages``."""
    found = vulns.lookup(packages, system)
    ids = [i for vuln_ids in found.values() for i in vuln_ids]
    return found, (vulns.summaries(ids) if details and ids else {})


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
    found, details = {}, {}
    if args.vulns:
        found, details = check_vulns(diff.new_packages(changes), pair[1]["os"])
    if args.json:
        extra = {"vulns": vulns.to_dict(found, details)} if args.vulns else {}
        print(diff_json(changes, skipped, **extra))
    else:
        print("\n".join(diff.to_lines(changes)) or "no changes")
        for name, reason in skipped.items():
            if diff.noteworthy(reason):
                print(f"note: {name} not compared ({reason})")
        for line in vulns.report(found, details):
            print(line)
    if found or diff.alerts(changes):
        return EXIT_VULNS
    return EXIT_OK if diff.is_empty(changes) else EXIT_CHANGES


def load_one(args):
    """Return the snapshot named by ``args.file``, else the newest saved one."""
    if args.file:
        return snapshot.load(args.file)
    found = snapshot.latest(snapshot.history(snapshot.state_dir(args.state_dir)))
    if found is None:
        raise ValueError("no snapshot yet, run bomwatch scan first")
    return found[1]


def cmd_export(args):
    """Write a snapshot as a CycloneDX or SPDX JSON document."""
    document = export.export(load_one(args), args.format)
    text = json.dumps(document, indent=1, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_audit(args):
    """Print every flagged record of a snapshot: what a person should look at."""
    snap = load_one(args)
    flagged = sorted(p for p in snap["packages"] if p.flags)
    if args.json:
        print(json.dumps([p.to_dict() for p in flagged], sort_keys=True))
    elif not flagged:
        print("nothing flagged")
    for pkg in flagged if not args.json else []:
        print(f"! {pkg.ecosystem} {pkg.name} ({pkg.location}) [{pkg.flags}]")
        # Sources that are a command line or a URL say what will run.
        if " " in pkg.source or "/" in pkg.source:
            print(f"    {pkg.source}")
    return EXIT_VULNS if flagged else EXIT_OK


def cmd_vulns(args):
    """Look up every package of a snapshot on osv.dev."""
    snap = load_one(args)
    found, details = check_vulns(snap["packages"], snap["os"], not args.no_details)
    if args.json:
        print(json.dumps(vulns.to_dict(found, details), sort_keys=True))
    else:
        print("\n".join(vulns.report(found, details)) or "no known vulnerabilities")
    return EXIT_VULNS if found else EXIT_OK


def cmd_log(args):
    """Print when a package appeared, changed and went away."""
    files = snapshot.history(snapshot.state_dir(args.state_dir))
    found = history.events(files, args.name, args.ecosystem, collectors.USES_ROOTS)
    if args.json:
        print(json.dumps(history.to_dict(found), sort_keys=True))
    elif found:
        print("\n".join(history.to_lines(found)))
    else:
        print(f"{args.name}: not in any scan")
    return EXIT_OK


def watch_once(args, base):
    """Scan once; save and print the scan when something changed.

    Returns True when there were changes.
    """
    snap = take_scan(args)
    live = {**snap, "packages": [Package(**p) for p in snap["packages"]]}
    old = baseline_for(live, snapshot.history(base))
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if old is None:
        path = snapshot.save(snap, base)
        if not args.json:
            print(f"{stamp} first scan, {len(snap['packages'])} packages, saved {path}")
        return False
    changes, skipped = compare_pair(old, live)
    if diff.is_empty(changes):
        return False
    path = snapshot.save(snap, base)
    found, details = {}, {}
    if args.vulns:
        try:
            found, details = check_vulns(diff.new_packages(changes), snap["os"])
        except OSError as exc:
            print(f"bomwatch: osv.dev: {exc}", file=sys.stderr)
    if args.json:
        extra = {"vulns": vulns.to_dict(found, details)} if args.vulns else {}
        print(diff_json(changes, skipped, time=stamp, snapshot=str(path), **extra))
    else:
        for line in diff.to_lines(changes) + vulns.report(found, details):
            print(f"{stamp} {line}")
    sys.stdout.flush()
    return True


def cmd_watch(args):
    """Scan every ``--interval`` seconds and print what changed, until stopped."""
    base = snapshot.state_dir(args.state_dir)
    done = 0
    try:
        while True:
            watch_once(args, base)
            done += 1
            if args.count and done >= args.count:
                return EXIT_OK
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return EXIT_OK


def cmd_prune(args):
    """Delete all but the newest ``--keep`` snapshots."""
    base = snapshot.state_dir(args.state_dir)
    if args.dry_run:
        files = snapshot.history(base)
        doomed = files[: max(len(files) - args.keep, 0)]
    else:
        doomed = snapshot.prune(base, args.keep)
    verb = "would delete" if args.dry_run else "deleted"
    for path in doomed:
        print(f"{verb} {path}")
    print(f"{verb} {len(doomed)} snapshots")
    return EXIT_OK


def setup_output(verbose):
    """Log to stderr at the asked level; never crash on a character the
    console cannot show."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    level = logging.WARNING - 10 * min(verbose, 2)
    logging.basicConfig(level=level, format="bomwatch: %(message)s", force=True)


def main(argv=None):
    """Run the command line interface and return an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    setup_output(args.verbose)
    try:
        return args.func(args)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except (OSError, ValueError) as exc:
        print(f"bomwatch: {exc}", file=sys.stderr)
        return EXIT_ERROR
