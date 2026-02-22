"""
Verification tests for the fixed SkillPipeline.

Run from the repo root:
    python -m backend.skills.test_pipeline
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.skills.pipeline import SkillPipeline, _wants_execution, _extract_last_target

pipeline = SkillPipeline()

RECON_HISTORY = [
    {"role": "user",      "content": "scan 192.168.1.54"},
    {"role": "assistant", "content": "Running Nmap scan report...\n[RECON] Open ports: 21/ftp, 22/ssh"},
]

EXPLOIT_HISTORY = [
    {"role": "user",      "content": "exploit the ftp service"},
    {"role": "assistant", "content": "[VECTOR] FTP allows anonymous login. Use: ftp 192.168.1.54"},
]

SCAN_HISTORY_ES = [
    {"role": "user",      "content": "escanea los puertos de 192.168.1.54"},
    {"role": "assistant", "content": "Nmap scan report for 192.168.1.54\n[RECON] Puerto 21/ftp, 22/ssh abiertos."},
]

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"

all_passed = True


def check(label, got, want):
    global all_passed
    ok = got == want
    if not ok:
        all_passed = False
    return ok


# ---------------------------------------------------------------------------
# Phase / dominant skill tests (original suite)
# ---------------------------------------------------------------------------

PHASE_TESTS = [
    # (description, team, input, history, expected_dominant, expected_fallback)
    (
        "test 1: red + scan",
        "red", "scan 192.168.1.54", [],
        "recon", False,
    ),
    (
        "test 2: red + 'what next?' + recon history (phase continuity)",
        "red", "what next?", RECON_HISTORY,
        "recon", True,
    ),
    (
        "test 3: red + exploit ftp",
        "red", "exploit the ftp service", [],
        "exploit", False,
    ),
    (
        "test 4: blue + open ports found, how to fix?",
        "blue", "open ports found, how to fix?", [],
        "defense", False,
    ),
    (
        "test 5: red + generate a report",
        "red", "generate a report", [],
        "reporting", False,
    ),
    (
        "test 6: red + no match, no history (default fallback)",
        "red", "hello there", [],
        "recon", True,
    ),
    (
        "test 7: red + exploit + report both match -> exploit wins (reporting suppressed)",
        "red", "exploit the service and write a report", [],
        "exploit", False,
    ),
]

print("=== Phase / Dominant Skill Tests ===")
for desc, team, inp, hist, exp_dominant, exp_fallback in PHASE_TESTS:
    _, decision = pipeline.build_prompt(inp, team, hist)
    ok = check(desc, decision.dominant_skill, exp_dominant) and \
         check(desc, decision.fallback_used, exp_fallback)
    status = PASS if ok else FAIL
    print(
        f"{status} {desc}\n"
        f"       dominant={decision.dominant_skill!r} (want {exp_dominant!r})"
        f"  fallback={decision.fallback_used} (want {exp_fallback})"
        f"  phase_hist={decision.phase_from_history!r}"
        f"  activated={decision.activated_skills}\n"
    )

# ---------------------------------------------------------------------------
# Target carry-over + execution intent tests (new)
# ---------------------------------------------------------------------------

print("=== Target Carry-Over + Execution Intent Tests ===")

# Test A: Spanish imperative with inline target
inp_a = "escanea los puertos de 192.168.1.54"
_, dec_a = pipeline.build_prompt(inp_a, "red", [])
ok_a_exec  = check("A exec",   dec_a.wants_execution, True)
ok_a_tgt   = check("A target", dec_a.last_target_used, "192.168.1.54")
ok_a = ok_a_exec and ok_a_tgt
print(
    f"{PASS if ok_a else FAIL} Test A: Spanish scan imperative with inline IP\n"
    f"       wants_execution={dec_a.wants_execution} (want True)"
    f"  last_target_used={dec_a.last_target_used!r} (want '192.168.1.54')"
    f"  dominant={dec_a.dominant_skill!r}\n"
)

# Test B: Follow-up with no target — must carry over IP from history
inp_b = "realiza una enumeracion de servicios"
_, dec_b = pipeline.build_prompt(inp_b, "red", SCAN_HISTORY_ES)
ok_b_exec  = check("B exec",   dec_b.wants_execution, True)
ok_b_tgt   = check("B target", dec_b.last_target_used, "192.168.1.54")
ok_b = ok_b_exec and ok_b_tgt
print(
    f"{PASS if ok_b else FAIL} Test B: Follow-up with no target (carry-over from history)\n"
    f"       wants_execution={dec_b.wants_execution} (want True)"
    f"  last_target_used={dec_b.last_target_used!r} (want '192.168.1.54')"
    f"  dominant={dec_b.dominant_skill!r}\n"
)

# Test C: Conceptual question — no execution intent
inp_c = "how does nmap work?"
_, dec_c = pipeline.build_prompt(inp_c, "red", [])
ok_c = check("C no-exec", dec_c.wants_execution, False)
print(
    f"{PASS if ok_c else FAIL} Test C: Conceptual question -> no execution intent\n"
    f"       wants_execution={dec_c.wants_execution} (want False)"
    f"  last_target_used={dec_c.last_target_used!r}\n"
)

# Test D: Composer injects CONTEXT TARGET section when carry-over + exec
prompt_d, _ = pipeline.build_prompt("realiza una enumeracion de servicios", "red", SCAN_HISTORY_ES)
ok_d = "CONTEXT TARGET" in prompt_d and "192.168.1.54" in prompt_d
if not ok_d:
    all_passed = False
print(
    f"{PASS if ok_d else FAIL} Test D: Composer injects CONTEXT TARGET on carry-over + exec\n"
    f"       CONTEXT TARGET in prompt: {'CONTEXT TARGET' in prompt_d}"
    f"  IP in prompt: {'192.168.1.54' in prompt_d}\n"
)

# Test E: Anti-fabrication rule present in all prompts
prompt_e, _ = pipeline.build_prompt("hello", "red", [])
ok_e = "Never fabricate" in prompt_e
if not ok_e:
    all_passed = False
print(
    f"{PASS if ok_e else FAIL} Test E: Anti-fabrication rule present in prompt\n"
    f"       'Never fabricate' in prompt: {ok_e}\n"
)

print("=" * 60)
print("ALL TESTS PASSED" if all_passed else "SOME TESTS FAILED")
sys.exit(0 if all_passed else 1)
