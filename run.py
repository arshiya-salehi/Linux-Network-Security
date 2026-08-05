"""Runs the simulated network and your mitm.py against the victim."""

import os
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def _spawn(name, role, cmd):
    env = os.environ.copy()
    env["CS130_ROLE"] = role
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    threading.Thread(target=_pipe, args=(name, proc.stdout),
                     daemon=True).start()
    return proc


def _pipe(name, stream):
    for line in stream:
        sys.stdout.write(f"{name} | {line}")
        sys.stdout.flush()


def _kill_all(procs):
    for p in procs:
        if p and p.poll() is None:
            try:
                p.terminate()
            except OSError:
                pass
    deadline = time.time() + 3
    for p in procs:
        if p and p.poll() is None:
            try:
                p.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                p.kill()


def main():
    os.makedirs(os.path.join(ROOT, "output"), exist_ok=True)
    pcap_path = os.path.join(ROOT, "output", "packetdump.pcap")
    if os.path.exists(pcap_path):
        os.remove(pcap_path)

    procs = []
    procs.append(_spawn("bus   ", "bus",
                        [PY, "-m", "network.bus", "--pcap", pcap_path]))
    time.sleep(0.5)
    procs.append(_spawn("dns   ", "dns",  [PY, "-m", "network.dns_server"]))
    procs.append(_spawn("bank  ", "bank", [PY, "-m", "network.bank_server"]))
    time.sleep(0.7)
    procs.append(_spawn("mitm  ", "mitm", [PY, "mitm.py"]))
    time.sleep(1.2)
    victim = _spawn("victim", "victim", [PY, "-m", "network.victim"])
    procs.append(victim)
    try:
        victim.wait(timeout=30)
    except subprocess.TimeoutExpired:
        print("[run] victim timed out", file=sys.stderr)

    time.sleep(0.5)
    _kill_all(procs)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
