import argparse
import datetime
import json
import os
import pathlib
import platform
import re
import socket
import statistics
import subprocess


def output(*command):
    return subprocess.check_output(command, text=True).strip()


def run_pair(directory, size, count, profile_dir=None, upstream=False, workers=None):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        endpoint = f"tcp://127.0.0.1:{reserved.getsockname()[1]}"
    arguments = [endpoint, str(size), str(count + int(upstream))]
    environment = os.environ.copy()
    if workers is not None:
        environment["TOKIO_WORKER_THREADS"] = str(workers)
    suffix = ".exe" if os.name == "nt" else ""
    receiver = subprocess.Popen([str(directory / f"local_thr{suffix}"), *arguments], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=environment)
    sender = None
    samplers = []
    try:
        sender = subprocess.Popen([str(directory / f"remote_thr{suffix}"), *arguments], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=environment)
        if profile_dir:
            profile_dir.mkdir(parents=True, exist_ok=True)
            for role, process in [("receiver", receiver), ("sender", sender)]:
                samplers.append(subprocess.Popen(["sample", str(process.pid), "3", "1", "-file", str(profile_dir / f"{role}.txt")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        sender_log, _ = sender.communicate(timeout=120)
        receiver_log, _ = receiver.communicate(timeout=15)
        if sender.returncode or receiver.returncode:
            raise RuntimeError(f"sender: {sender_log}\nreceiver: {receiver_log}")
        match = re.search(r"^(?:mean )?throughput: ([\d.]+) (?:msg/s|\[msg/s\])", receiver_log, re.MULTILINE)
        if not match:
            raise RuntimeError(receiver_log)
        for sampler in samplers:
            if sampler.wait(timeout=10):
                raise RuntimeError("sample failed to capture the process")
        rate = float(match[1])
        return rate * count / (count + 1) if upstream else rate
    finally:
        for process in [sender, receiver, *samplers]:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--celerity-dir", type=pathlib.Path, default=pathlib.Path("target/release"))
    parser.add_argument("--libzmq-dir", type=pathlib.Path)
    parser.add_argument("--libzmq-version", default="unspecified")
    parser.add_argument("--count", type=int, default=1_000_000)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1, 64, 1024])
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--compare-workers", action="store_true")
    parser.add_argument("--profile-dir", type=pathlib.Path)
    args = parser.parse_args()
    if min(args.count, args.runs, *args.sizes) <= 0:
        parser.error("counts, runs, and sizes must be positive")
    if args.profile_dir and platform.system() != "Darwin":
        parser.error("--profile-dir requires macOS sample")
    implementations = {"celerity": args.celerity_dir.resolve()}
    if args.libzmq_dir:
        implementations["libzmq"] = args.libzmq_dir.resolve()
    if args.compare_workers:
        implementations["celerity-1-worker"] = args.celerity_dir.resolve()
    result = {
        "date_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "revision": output("git", "rev-parse", "HEAD"),
        "dirty": bool(output("git", "status", "--porcelain")),
        "rustc": output("rustc", "--version"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": output("sysctl", "-n", "machdep.cpu.brand_string") if platform.system() == "Darwin" else platform.processor(),
        "tokio_worker_threads": os.environ.get("TOKIO_WORKER_THREADS", "default"),
        "timed_messages": args.count,
        "libzmq_version": args.libzmq_version if args.libzmq_dir else None,
        "logical_cpus": os.cpu_count(),
        "dependencies": output("cargo", "tree", "--features", "tokio", "--prefix", "none").replace(str(pathlib.Path.cwd()), "."),
        "runs": args.runs,
        "transport": "TCP loopback, NULL",
        "samples": [],
    }
    for size in args.sizes:
        samples = {name: [] for name in implementations}
        for repetition in range(args.runs):
            order = list(implementations.items())
            if repetition % 2:
                order.reverse()
            for name, directory in order:
                rate = run_pair(directory, size, args.count, upstream=name == "libzmq", workers=1 if name == "celerity-1-worker" else None)
                samples[name].append(rate)
                print(f"{name} {size}B run {repetition + 1}: {rate:,.0f} msg/s", flush=True)
        for name, rates in samples.items():
            result["samples"].append({"implementation": name, "size": size, "msg_per_second": rates, "median": statistics.median(rates)})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    if args.profile_dir:
        run_pair(args.celerity_dir.resolve(), 1, 10_000_000, args.profile_dir.resolve())


if __name__ == "__main__":
    main()
