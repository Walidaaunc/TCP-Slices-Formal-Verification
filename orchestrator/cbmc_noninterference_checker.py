import os
import subprocess
import re
import time
import psutil
import threading

# Helper to locate the first assignment of a variable in a CBMC trace
def get_first_val(pattern, text):
    matches = re.findall(pattern, text)
    return matches[0] if matches else "None"

# Helper to locate the last assignment of a variable in a CBMC trace
def get_last_val(pattern, text):
    matches = re.findall(pattern, text)
    return matches[-1] if matches else None

def analyze_vulnerability(filename, isDkBoundPresent, k_val=None, log_file=None):
    # Helper to write output to both a file and the terminal
    def log(msg):
        print(msg, file=log_file)
        print(msg)

    header_suffix = f" (K={k_val})" if k_val else ""

    log(f"\n{'='*60}")
    log(f"[*] AUTOMATED NON-INTERFERENCE CHECKER")
    log(f"[*] Target Model: {filename}{header_suffix}")
    log(f"{'='*60}")

    # Builds the command
    full_path = os.path.join('../models/', filename)
    cmd = ["cbmc", full_path, "--trace"]
    if isDkBoundPresent:
        # Using a variation of K and setting the unwind bound to K + 1 accordingly
        cmd.extend([f"-DK_BOUND={k_val}", "--unwind", str(k_val + 1), "--unwinding-assertions"])

    start_time = time.perf_counter()
    max_mem = 0
    output_parts = []

    def stream_reader(pipe):
        # Worker thread to read output and prevent buffer deadlocks
        for line in iter(pipe.readline, ''):
            output_parts.append(line)
        pipe.close()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1 # Line buffered
        )

        # Launches threads to drain stdout and stderr pipes
        t1 = threading.Thread(target=stream_reader, args=(proc.stdout,))
        t2 = threading.Thread(target=stream_reader, args=(proc.stderr,))
        t1.start()
        t2.start()

        ps_proc = psutil.Process(proc.pid)

        # Tracks memory usage while threads process the output
        while proc.poll() is None:
            try:
                # Gets memory usage of the process and all its child processes (since CBMC may spawn subprocesses)
                mem = ps_proc.memory_info().rss
                for child in ps_proc.children(recursive=True):
                    mem += child.memory_info().rss
                if mem > max_mem:
                    max_mem = mem
                time.sleep(0.05)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

        t1.join()
        t2.join()
        output = "".join(output_parts)
        elapsed_time = time.perf_counter() - start_time

    except FileNotFoundError:
        log("[!] Error: 'cbmc' not found in PATH.")
        return

    if "VERIFICATION FAILED" in output:
        log("[!] RESULT: NON-INTERFERENCE VIOLATION DETECTED")
        log("-" * 60)

        # Extract high-security inputs (secrets)
        # and low-security inputs (attacker guess)
        secret_seq_num_1 = secret_seq_num_2 = victim_ip = None
        secret_port_1 = secret_port_2 = attacker_ip = None
        attacker_input = "None"

        if filename.startswith("port_inference"):
            secret_port_1 = get_first_val(r"secret_port_1=([-]?\d+)", output)
            secret_port_2 = get_first_val(r"secret_port_2=([-]?\d+)", output)
            attacker_input = get_first_val(r"attacker_port_guess=([-]?\d+)", output)
        elif filename.startswith("cve_2016_5696"):
            secret_seq_num_1 = get_first_val(r"secret_seq_num_1=([-]?\d+)", output)
            secret_seq_num_2 = get_first_val(r"secret_seq_num_2=([-]?\d+)", output)
            attacker_input = get_first_val(r"attacker_seq_num_guess=([-]?\d+)", output)
        elif filename.startswith("ipid_downgrade"):
            # Uses broader regex to catch variables regardless of scope
            secret_seq_num_1 = get_first_val(r"secret_seq_num_1=([-]?\d+)", output)
            secret_seq_num_2 = get_first_val(r"secret_seq_num_2=([-]?\d+)", output)
            victim_ip = get_first_val(r"victim_ip=([-]?\d+)", output)
            attacker_ip = get_first_val(r"attacker_ip=([-]?\d+)", output)

            # Captures array guesses: attacker_seq_num_guesses[0]=...
            guesses = re.findall(r"attacker_seq_num_guesses\[\d+l?\]=([0-9]+)", output)
            attacker_input = ", ".join(set(guesses)) if guesses else "None"

        # Extracts attacker's observations
        obs_1 = obs_2 = None

        if filename.startswith("port_inference"):
            obs_1 = get_last_val(r"time_1=([-]?\d+)", output)
            obs_2 = get_last_val(r"time_2=([-]?\d+)", output)
        elif filename.startswith("cve_2016_5696") or filename.startswith("ipid_downgrade"):
            obs_1 = get_last_val(r"attacker_observation_1=([-]?\d+)", output)
            obs_2 = get_last_val(r"attacker_observation_2=([-]?\d+)", output)

        # Logs results
        if filename.startswith("port_inference"):
            log(f"  [SECRET] Trace A Port: {secret_port_1} | Trace B Port: {secret_port_2}")
            log(f"  [INPUT]  Attacker Guess: {attacker_input}")
            log("-" * 30)
            log(f"  [OUTPUT] Time A: {obs_1}ms | Time B: {obs_2}ms")
        elif filename.startswith("cve_2016_5696") or filename.startswith("ipid_downgrade"):
            log(f"  [SECRET] Trace A Seq: {secret_seq_num_1} | Trace B Seq: {secret_seq_num_2}")
            if victim_ip:
                log(f"  [STATE]  Victim IP: {victim_ip}")
            if attacker_ip:
                log(f"  [INPUT]  Attacker IP: {attacker_ip}")
            log(f"  [INPUT]  Attacker Guesses: {attacker_input}")
            log("-" * 30)
            log(f"  [OUTPUT] Observation A: {obs_1} | Observation B: {obs_2}")

        log(f"  [CAUSE]  {'Timing Side-Channel' if 'port' in filename else 'Resource Contention'}")
        log("-" * 60)
        log("[Vulnerability Summary]")
        log("A counterexample was found where the attacker's observation")
        log("differed between two executions with identical attacker inputs,")
        log("proving that High-Security data has leaked into Low-Security outputs.")

    elif "VERIFICATION SUCCESSFUL" in output:
        log("[+] RESULT: NO VIOLATION FOUND (within bound K)")
        log("    The model checker proved that within the explored")
        log("    bound, the attacker cannot distinguish between secrets.")
    else:
        log("[?] STATUS: UNKNOWN")
        log("    Model checker produced an error or timed out.")

    # Logs performance data
    log("-" * 60)
    log(f"[Performance Metrics]")
    log(f"  Execution Time: {elapsed_time:.2f} seconds")
    log(f"  Peak Memory:    {max_mem / (1024*1024):.2f} MB")
    log("-" * 60)

if __name__ == "__main__":
    with open("results.txt", "w") as f:
        # Uses a predefined file list to avoid issues with directory traversal
        targets = [
            file for file in os.listdir('../models/')
            if file.endswith('vulnerability.c') or file.endswith('patch.c')
       ]
        for filename in sorted(targets):
            if filename.startswith("port_inference"):
                analyze_vulnerability(filename, isDkBoundPresent=False, log_file=f)
            elif filename.startswith("cve_2016_5696") or filename.startswith("ipid_downgrade"):
                # Runs 5 variations of K
                for k in [1, 2, 3, 5, 10]:
                    analyze_vulnerability(filename, isDkBoundPresent=True, k_val=k, log_file=f)