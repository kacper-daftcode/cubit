#!/usr/bin/env python3
"""Run cubit's test suite with the test binaries in parallel.

`cargo test` builds the ~470 integration-test binaries and then runs them one after another; the
tests inside a binary run on parallel threads, but most binaries hold a handful of tests, so the
suite spends most of its wall time with one core busy (the push gate of 2026-11-06: 471 binaries,
32 minutes on 16 cores, 31 of them the serial sum of the binaries' own run times). This runner
builds the binaries with `cargo test --no-run` (same flags, same artifacts), then runs them on a
pool of workers, longest first, and prints one summary line per binary plus the totals in the
`cargo test` vocabulary (passed / failed / ignored). Nothing about the tests changes: every binary
runs with the package root as its working directory (relative `tables/<arch>.json` paths resolve
as under `cargo test`), with its own `RUST_TEST_THREADS`, and its complete output is kept under
`<target>/test-suite/<binary>.log`.

    tools/test_suite.py --release                 # the push gate: everything, 16 workers x 2 threads
    tools/test_suite.py --release -j 8 -t 4       # 8 binaries at a time, 4 test threads each
    tools/test_suite.py --release --filter bug44  # binaries whose name contains "bug44"
    tools/test_suite.py --release -- --skip slow  # arguments after `--` go to every test binary

The order is longest-first from the previous run's timings (`<target>/test-suite/timings.json`),
by binary size the first time. Exit status 0 when every binary reports `test result: ok`, 1
otherwise (the failing binaries and their first failing lines are repeated at the end). The
`cargo test` baseline of the same tree is reproduced by `-j 1 -t <cores>`.
"""
import argparse
import concurrent.futures
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULT_RE = re.compile(
    r"^test result: (?P<status>ok|FAILED)\. (?P<passed>\d+) passed; (?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; (?P<filtered>\d+) filtered out"
    r"(?:; finished in (?P<secs>[\d.]+)s)?",
    re.M,
)


def cargo_test_binaries(cargo_args):
    """`cargo test --no-run --message-format=json` -> [(name, executable path)]."""
    cmd = ["cargo", "test", "--no-run", "--message-format=json"] + cargo_args
    proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, text=True, check=False)
    if proc.returncode != 0:
        sys.exit(f"cargo test --no-run failed (rc={proc.returncode}); run `cargo test --no-run` to see why")
    bins = []
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact" or not msg.get("executable"):
            continue
        if not msg.get("profile", {}).get("test"):
            continue
        target = msg.get("target", {})
        kind = target.get("kind", [])
        # unit tests of the library / binary and every integration test
        name = target.get("name", pathlib.Path(msg["executable"]).name)
        if "lib" in kind:
            name = f"{name} (lib)"
        elif "bin" in kind:
            name = f"{name} (bin)"
        bins.append((name, msg["executable"]))
    return bins


def target_dir(cargo_args):
    """The profile's target directory (for the logs and the timings), from cargo's own view."""
    meta = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True,
    )
    base = pathlib.Path(json.loads(meta.stdout)["target_directory"])
    profile = "release" if "--release" in cargo_args else "debug"
    for i, a in enumerate(cargo_args):
        if a == "--profile" and i + 1 < len(cargo_args):
            profile = cargo_args[i + 1]
    return base / profile


def run_one(name, exe, test_args, threads, logdir):
    log = logdir / (pathlib.Path(exe).name + ".log")
    env = dict(os.environ)
    env.setdefault("RUST_TEST_THREADS", str(threads))
    t0 = time.monotonic()
    with open(log, "w") as fh:
        proc = subprocess.run([exe] + test_args, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT,
                              env=env, check=False)
    wall = time.monotonic() - t0
    text = log.read_text(errors="replace")
    m = None
    for m in RESULT_RE.finditer(text):
        pass  # the last `test result:` line (a binary prints one)
    if m is None:
        return dict(name=name, exe=exe, rc=proc.returncode, wall=wall, status="NO RESULT",
                    passed=0, failed=0, ignored=0, log=str(log))
    return dict(name=name, exe=exe, rc=proc.returncode, wall=wall, status=m.group("status"),
                passed=int(m.group("passed")), failed=int(m.group("failed")),
                ignored=int(m.group("ignored")), log=str(log))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-j", "--jobs", type=int, default=None,
                    help="test binaries run at a time (default: the cores this process may use, max 16)")
    ap.add_argument("-t", "--threads", type=int, default=2,
                    help="RUST_TEST_THREADS per binary (default 2; the tests of one binary run on that many threads)")
    ap.add_argument("--filter", default=None, help="run only binaries whose name contains this string")
    ap.add_argument("--list", action="store_true", help="list the binaries in run order and exit")
    ap.add_argument("--slowest", type=int, default=15, help="how many of the slowest binaries to print (default 15)")
    ap.epilog = ("every other argument (e.g. --release, --profile <p>, --features <f>) is passed to "
                 "`cargo test --no-run`; arguments after `--` go to the test binaries")
    argv = sys.argv[1:]
    test_args = []
    if "--" in argv:
        i = argv.index("--")
        argv, test_args = argv[:i], argv[i + 1:]
    args, cargo_args = ap.parse_known_args(argv)
    args.cargo_args = cargo_args

    try:
        cores = len(os.sched_getaffinity(0))
    except AttributeError:  # not Linux
        cores = os.cpu_count() or 4
    jobs = args.jobs or max(1, min(16, cores))

    tdir = target_dir(args.cargo_args)
    logdir = tdir / "test-suite"
    logdir.mkdir(parents=True, exist_ok=True)
    timings_path = logdir / "timings.json"
    timings = {}
    if timings_path.exists():
        try:
            timings = json.loads(timings_path.read_text())
        except json.JSONDecodeError:
            timings = {}

    t_build = time.monotonic()
    bins = cargo_test_binaries(args.cargo_args)
    t_build = time.monotonic() - t_build
    if args.filter:
        bins = [b for b in bins if args.filter in b[0]]
    if not bins:
        sys.exit("no test binaries selected")
    # longest first: last run's wall time, else the binary size as a proxy
    bins.sort(key=lambda b: (-timings.get(b[0], 0.0), -os.path.getsize(b[1])))
    if args.list:
        for name, exe in bins:
            print(f"{timings.get(name, 0.0):8.2f}s  {name}")
        return 0

    print(f"{len(bins)} test binaries built in {t_build:.0f}s; running {jobs} at a time, "
          f"RUST_TEST_THREADS={args.threads}, logs in {logdir}", flush=True)
    t0 = time.monotonic()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futs = [pool.submit(run_one, name, exe, test_args, args.threads, logdir) for name, exe in bins]
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            results.append(r)
            flag = "ok  " if r["status"] == "ok" and r["rc"] == 0 else "FAIL"
            print(f"{flag} {r['wall']:7.2f}s  {r['passed']:4d} passed {r['failed']:3d} failed "
                  f"{r['ignored']:2d} ignored  {r['name']}", flush=True)
    wall = time.monotonic() - t0

    for r in results:
        timings[r["name"]] = r["wall"]
    timings_path.write_text(json.dumps(timings, indent=1, sort_keys=True))

    passed = sum(r["passed"] for r in results)
    failed = sum(r["failed"] for r in results)
    ignored = sum(r["ignored"] for r in results)
    bad = [r for r in results if r["status"] != "ok" or r["rc"] != 0]
    results.sort(key=lambda r: -r["wall"])
    print(f"\nslowest {min(args.slowest, len(results))} binaries:")
    for r in results[: args.slowest]:
        print(f"  {r['wall']:7.2f}s  {r['name']}")
    print(f"\n{len(results)} binaries, {passed} passed / {failed} failed / {ignored} ignored, "
          f"{wall / 60:.1f} min wall (binaries' own run time {sum(r['wall'] for r in results) / 60:.1f} min), "
          f"build {t_build:.0f}s")
    if bad:
        print(f"\n{len(bad)} binaries not ok:")
        for r in sorted(bad, key=lambda r: r["name"]):
            print(f"  {r['name']}: {r['status']} rc={r['rc']} ({r['log']})")
            text = pathlib.Path(r["log"]).read_text(errors="replace")
            for line in text.splitlines():
                if line.startswith("test ") and line.rstrip().endswith("FAILED"):
                    print(f"      {line.strip()}")
            if r["status"] == "NO RESULT":
                tail = text.strip().splitlines()[-5:]
                for line in tail:
                    print(f"      {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
