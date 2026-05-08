# Formal Verification of TCP State Machine Slices

---

## Project Structure  

### `/models`  
These models simulate simplified TCP connections and use self-composition with nondeterministic inputs to determine whether an attacker can deduce the victim's secrets from side-channel leakage.

- `port_inference_vulnerability.c`  
  Models a timing side-channel in which an off-path attacker infers a secret TCP port by observing execution delays that differ based on whether a guessed value matches the victim's state.

- `port_inference_patch.c`  
  Implements a constant-time mitigation by normalizing execution behavior across matching and non-matching cases, thereby eliminating timing-based leakage.

- `cve_2016_5696_vulnerability.c`  
  Models a side-channel in which an attacker infers a victim's TCP sequence number by exploiting a shared Challenge ACK counter and observing depletion patterns via probing.

- `cve_2016_5696_patch.c`  
  Fixes the vulnerability by replacing a shared global counter with per-connection counters, isolating state updates, and preventing cross-connection leakage.

- `ipid_downgrade_vulnerability.c`  
  Models a downgrade-based attack where an adversary forces a transition from per-socket IPID assignment to a shared global counter, enabling inference of connection state via observed counter updates.

- `ipid_downgrade_patch.c`  
  Enforces strict per-socket IPID assignment and restricts shared counters to non-TCP traffic, removing the shared resource dependency used in inference.

---

### `/orchestrator`

- `cbmc_noninterference_checker.py`  
  A Python-based automation script that detects side-channel leakage through self-composition. This script invokes models that execute two program instances with distinct secret inputs and generate attacker-visible outputs. Upon detecting divergence, this script extracts counterexamples via regex-based parsing and logs the results in a structured format. The script supports multiple bounded exploration depths via K-unrolling and employs threading to monitor performance metrics.

- `results.txt`  
  A structured log of verification outcomes and performance metrics for each model. Each run reports one of three states:  
  - **NON-INTERFERENCE VIOLATION DETECTED**: A counterexample exists showing observable leakage of secret data into attacker-visible outputs.  
  - **NO VIOLATION FOUND**: No leakage is detected within the given bounded model.  
  - **UNKNOWN**: The verification is inconclusive due to a timeout or internal limitations.  

  Results are recorded across multiple unrolling bounds \(K ∈ {1, 2, 3, 5, 10}\) to evaluate scalability. Each entry includes execution time (seconds) and peak memory usage (MB).

---

### `/plots`

- `memory_plot.py`  
  Generates a logarithmic line plot comparing peak memory usage across models as K increases.

- `time_plot.py`  
  Generates a logarithmic line plot comparing execution time across models as K increases.

---

## Execution Steps

### 1. Setup

Download the source code.

Install CBMC:
- macOS (Homebrew):
```bash
brew install cbmc
```
* Other systems: [https://www.cprover.org/cbmc/](https://www.cprover.org/cbmc/)

---

### 2. Run individual models

```bash
cd models
```

Port inference:

```bash
cbmc port_inference_vulnerability.c --trace
cbmc port_inference_patch.c --trace
```

CVE-2016-5696 (bounded):

```bash
cbmc cve_2016_5696_vulnerability.c --trace -DK_BOUND={k} --unwind {k + 1} --unwinding-assertions
cbmc cve_2016_5696_patch.c --trace -DK_BOUND={k} --unwind {k + 1} --unwinding-assertions
```

IPID downgrade (bounded):

```bash
cbmc ipid_downgrade_vulnerability.c --trace -DK_BOUND={k} --unwind {k + 1} --unwinding-assertions
cbmc ipid_downgrade_patch.c --trace -DK_BOUND={k} --unwind {k + 1} --unwinding-assertions
```

---

### 3. Run orchestration script

```bash
cd orchestrator
pip install <required_libraries>
python -m cbmc_noninterference_checker
```

The script streams logs in real time and writes structured results to `results.txt`.
