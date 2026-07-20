import time
from datetime import datetime
import logging

logger = logging.getLogger("ebpf_sensor")

def capture_ebpf_kernel_events(container_id: str, processes: list = None) -> list:
    """Simulates eBPF probe syscall capture (sys_execve, sys_connect, sys_mount) for container PID namespaces."""
    events = []
    if not processes:
        processes = ["nginx: master process"]

    for idx, proc in enumerate(processes):
        proc_str = str(proc)
        pid = 10000 + idx * 42 + 7
        t_stamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if any(b in proc_str.lower() for b in ["nc", "sh -c", "bash -i"]):
            events.append({
                "probe": "kprobe:sys_execve",
                "pid": pid,
                "process": proc_str,
                "syscall": "sys_execve",
                "args": ["/bin/sh", "-c", "nc -l -p 4444"],
                "verdict": "CRITICAL_ANOMALY",
                "timestamp": t_stamp
            })
        elif "xmrig" in proc_str.lower() or "miner" in proc_str.lower():
            events.append({
                "probe": "kprobe:sys_sched_setaffinity",
                "pid": pid,
                "process": proc_str,
                "syscall": "sys_sched_setaffinity",
                "args": ["CPU_MASK_ALL_CORES"],
                "verdict": "RESOURCE_HIJACK",
                "timestamp": t_stamp
            })
        elif "chmod" in proc_str.lower() or "nsenter" in proc_str.lower():
            events.append({
                "probe": "kprobe:sys_mount",
                "pid": pid,
                "process": proc_str,
                "syscall": "sys_mount",
                "args": ["/proc/1/ns/mnt", "/host"],
                "verdict": "PRIVILEGE_ESCALATION",
                "timestamp": t_stamp
            })
        else:
            events.append({
                "probe": "kprobe:sys_execve",
                "pid": pid,
                "process": proc_str,
                "syscall": "sys_execve",
                "args": [proc_str],
                "verdict": "NORMAL",
                "timestamp": t_stamp
            })

    return events
