"""Docker terminal SSE bridge — cross-platform.

Linux / macOS:  real PTY via pty.openpty() + ``docker exec -it``
                → full interactive support (vim, nano, top, htop, etc.)

Windows:        subprocess pipes via ``docker exec -i``
                → basic shell, no curses programs, no resize
                Uses threading + subprocess.Popen because uvicorn --reload
                on Windows forces SelectorEventLoop which does NOT support
                asyncio.create_subprocess_exec.

Output is streamed via SSE (base64-encoded); input is received via POST.
"""

import re
import shutil
import os
import sys
import asyncio
import json
import subprocess
import threading
import queue
import uuid
import base64
from typing import AsyncGenerator

# Unix-only imports — guarded so the module loads on Windows too.
if sys.platform != "win32":
    import pty
    import fcntl
    import struct
    import termios
    import signal
    import subprocess as _subprocess  # only used by the PTY path

IS_UNIX = sys.platform != "win32"

CONTAINER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")

_docker_container: str = ""


def set_docker_container(name: str):
    global _docker_container
    _docker_container = name


def get_docker_container() -> str:
    return _docker_container


# ---------------------------------------------------------------------------
# Shared helpers — work on every platform
# ---------------------------------------------------------------------------

async def _run_cmd(*args, capture_stdout=False) -> tuple[int, bytes]:
    """Run a command and return (returncode, stdout_bytes).

    Uses subprocess.run in a thread — works with any event loop.
    """
    loop = asyncio.get_event_loop()

    def _exec():
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode, result.stdout or b""

    return await loop.run_in_executor(None, _exec)


async def _check_docker() -> bool:
    if not shutil.which("docker"):
        return False
    rc, _ = await _run_cmd("docker", "info")
    return rc == 0


async def _container_exists(name: str) -> bool:
    rc, _ = await _run_cmd("docker", "inspect", name)
    return rc == 0


async def _container_running(name: str) -> bool:
    rc, out = await _run_cmd(
        "docker", "inspect", "-f", "{{.State.Running}}", name,
        capture_stdout=True,
    )
    return out.strip() == b"true"


async def _start_container(name: str) -> bool:
    rc, _ = await _run_cmd("docker", "start", name)
    return rc == 0


async def _detect_shell(container: str) -> str:
    rc, _ = await _run_cmd("docker", "exec", container, "which", "bash")
    return "bash" if rc == 0 else "sh"


async def _has_script(container: str) -> bool:
    """Check if the ``script`` utility is available inside the container."""
    rc, _ = await _run_cmd("docker", "exec", container, "which", "script")
    return rc == 0


async def _validate_and_prepare(container: str) -> tuple[str | None, str | None]:
    """Run all pre-flight checks.

    Returns (shell, None) on success, or (None, error_message) on failure.
    """
    if not container or not CONTAINER_RE.match(container):
        return None, "Error: No valid Docker container configured. Set it in Settings > Docker Terminal."

    if not await _check_docker():
        return None, "Error: Docker is not available."

    if not await _container_exists(container):
        return None, f"Error: Container '{container}' not found."

    started_msg = None
    if not await _container_running(container):
        if not await _start_container(container):
            return None, "Failed to start container."
        started_msg = "started"

    shell = await _detect_shell(container)
    return shell, started_msg


# ---------------------------------------------------------------------------
# Terminal Session
# ---------------------------------------------------------------------------

class TerminalSession:
    """Holds a docker exec subprocess and provides output via a queue."""

    def __init__(self, session_id: str, container: str, shell: str):
        self.session_id = session_id
        self.container = container
        self.shell = shell
        self.stop_event = threading.Event()
        self.out_q: queue.Queue[bytes | None] = queue.Queue()
        self.proc = None
        self.master_fd = None  # Unix PTY only
        self._reader_thread = None

    def start_pipe(self, use_script: bool = False):
        """Start docker exec with pipes (Windows).

        When *use_script* is True, the ``script`` utility is used to
        allocate a real PTY **inside** the container.  This gives proper
        echo, prompt, and line-editing — the closest to a real terminal
        we can get without host-side PTY support.

        Falls back to ``bash -i`` (interactive but no PTY) when
        ``script`` is not available in the container.
        """
        if use_script:
            cmd = [
                "docker", "exec", "-i", self.container,
                "script", "-q", "-c", self.shell, "/dev/null",
            ]
        else:
            cmd = [
                "docker", "exec", "-i", self.container,
                self.shell, "-i",
            ]
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._reader_thread = threading.Thread(target=self._pipe_reader, daemon=True)
        self._reader_thread.start()

    # Bash warnings that appear in pipe mode (no real PTY).
    _PIPE_WARNINGS = (
        b"bash: cannot set terminal process group",
        b"bash: no job control in this shell",
    )

    def _pipe_reader(self):
        suppress = 5  # filter bash warnings in the first few chunks
        try:
            while not self.stop_event.is_set():
                # read1() returns whatever is buffered without waiting for
                # a full buffer — much faster than read(1).
                data = self.proc.stdout.read1(4096)
                if not data:
                    break

                # No PTY driver → must convert \n to \r\n ourselves
                # (normalise first so existing \r\n doesn't become \r\r\n)
                data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")

                # Suppress well-known bash pipe-mode warnings at startup
                if suppress > 0:
                    suppress -= 1
                    for w in self._PIPE_WARNINGS:
                        # The warning can appear with various suffixes
                        idx = data.find(w)
                        while idx != -1:
                            # Find end of that line (\r\n after our conversion)
                            end = data.find(b"\r\n", idx)
                            if end == -1:
                                data = data[:idx]
                            else:
                                data = data[:idx] + data[end + 2:]
                            idx = data.find(w)
                    if not data.strip(b"\r\n"):
                        continue

                self.out_q.put(data)
        except Exception:
            pass
        finally:
            self.out_q.put(None)

    def start_pty(self):
        """Start docker exec with a real PTY (Unix only)."""
        master_fd, slave_fd = pty.openpty()
        self.master_fd = master_fd

        winsize = struct.pack("HHHH", 24, 80, 0, 0)
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)

        self.proc = _subprocess.Popen(
            ["docker", "exec", "-it", self.container, self.shell],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            preexec_fn=os.setsid,
        )
        os.close(slave_fd)

        self._reader_thread = threading.Thread(target=self._pty_reader, daemon=True)
        self._reader_thread.start()

    def _pty_reader(self):
        try:
            while not self.stop_event.is_set():
                try:
                    data = os.read(self.master_fd, 4096)
                    if not data:
                        break
                    self.out_q.put(data)
                except OSError:
                    break
        except Exception:
            pass
        finally:
            self.out_q.put(None)

    def write_stdin(self, data: bytes):
        """Write data to the process stdin."""
        if IS_UNIX and self.master_fd is not None:
            try:
                os.write(self.master_fd, data)
            except OSError:
                pass
        elif self.proc and self.proc.stdin:
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except OSError:
                pass

    def resize(self, cols: int, rows: int):
        """Resize PTY (Unix only, no-op on Windows)."""
        if not IS_UNIX or self.master_fd is None:
            return
        try:
            ws_data = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, ws_data)
            if self.proc and self.proc.poll() is None:
                os.kill(self.proc.pid, signal.SIGWINCH)
        except (OSError, ProcessLookupError):
            pass

    def destroy(self):
        """Kill process and clean up resources."""
        self.stop_event.set()

        if self.proc and self.proc.poll() is None:
            if IS_UNIX:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    pass
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        pass
                    self.proc.wait()
            else:
                try:
                    self.proc.terminate()
                except ProcessLookupError:
                    pass
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait()

        if IS_UNIX and self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

        if self._reader_thread:
            self._reader_thread.join(timeout=2)

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


# ---------------------------------------------------------------------------
# Session registry
# ---------------------------------------------------------------------------

_sessions: dict[str, TerminalSession] = {}


async def create_session(container: str) -> tuple[str | None, str | None, list[str]]:
    """Create a new terminal session.

    Returns (session_id, error_message, info_messages).
    On success error_message is None. On failure session_id is None.
    """
    info: list[str] = []
    shell, status = await _validate_and_prepare(container)
    if shell is None:
        # status is the error message
        return None, status, info

    if status == "started":
        info.append(f"Container '{container}' was stopped — started it.")

    session_id = uuid.uuid4().hex[:12]
    session = TerminalSession(session_id, container, shell)

    if IS_UNIX:
        session.start_pty()
    else:
        use_script = await _has_script(container)
        session.start_pipe(use_script=use_script)

    # Wait for output to start arriving (up to 3 s) so we know the
    # shell is alive and producing its startup noise.
    for _ in range(30):
        if not session.out_q.empty():
            break
        await asyncio.sleep(0.1)

    if not session.alive:
        # Drain any error output from the queue
        err_parts = []
        while not session.out_q.empty():
            chunk = session.out_q.get_nowait()
            if chunk:
                err_parts.append(chunk.decode("utf-8", errors="replace"))
        session.destroy()
        detail = "".join(err_parts).strip() or "Process exited immediately"
        return None, detail, info

    # Let remaining startup noise finish (double prompt, warnings, etc.)
    await asyncio.sleep(0.3)

    # Drain all startup output, set a coloured prompt, and clear the
    # screen so the user sees a single clean prompt with no noise.
    if not IS_UNIX:
        while not session.out_q.empty():
            chunk = session.out_q.get_nowait()
            if chunk is None:
                session.out_q.put(None)  # re-queue sentinel
                break
        # Set TERM (needed by curses programs), bold bright-white
        # prompt, then clear screen with raw ANSI escapes (works
        # without TERM).  This wipes startup noise + double prompt.
        session.write_stdin(
            b"export TERM=xterm PS1='\\[\\033[1;37m\\]\\u@\\h:\\w\\$ \\[\\033[0m\\]'; printf '\\033[2J\\033[H'\n"
        )

    _sessions[session_id] = session
    return session_id, None, info


def get_session(session_id: str) -> TerminalSession | None:
    return _sessions.get(session_id)


def destroy_session(session_id: str):
    session = _sessions.pop(session_id, None)
    if session:
        session.destroy()


async def output_generator(session_id: str) -> AsyncGenerator[dict, None]:
    """Async generator yielding SSE events with base64-encoded terminal output."""
    session = _sessions.get(session_id)
    if not session:
        yield {"event": "error", "data": json.dumps({"error": "Session not found"})}
        return

    loop = asyncio.get_event_loop()

    while not session.stop_event.is_set():
        try:
            first = await loop.run_in_executor(
                None, lambda: session.out_q.get(timeout=0.5)
            )
        except queue.Empty:
            if not session.alive and session.out_q.empty():
                break
            continue

        if first is None:
            break

        # Batch: drain any additional bytes already queued
        buf = bytearray(first)
        while not session.out_q.empty():
            try:
                extra = session.out_q.get_nowait()
                if extra is None:
                    session.out_q.put(None)  # re-queue sentinel
                    break
                buf.extend(extra)
            except queue.Empty:
                break

        encoded = base64.b64encode(bytes(buf)).decode("ascii")
        yield {"event": "output", "data": json.dumps({"b64": encoded})}

    yield {"event": "exit", "data": json.dumps({"reason": "process exited"})}


def send_input(session_id: str, data: bytes) -> bool:
    """Write input bytes to a session. Returns False if session not found."""
    session = _sessions.get(session_id)
    if not session:
        return False
    session.write_stdin(data)
    return True


def resize_session(session_id: str, cols: int, rows: int) -> bool:
    """Resize terminal. Returns False if session not found."""
    session = _sessions.get(session_id)
    if not session:
        return False
    session.resize(cols, rows)
    return True


# ---------------------------------------------------------------------------
# Tor transparent proxy helpers
# ---------------------------------------------------------------------------

async def _check_net_admin(container: str) -> bool:
    """Check if container has NET_ADMIN capability or is privileged."""
    rc, out = await _run_cmd(
        "docker", "inspect",
        "--format={{.HostConfig.Privileged}}{{range .HostConfig.CapAdd}}{{.}}{{end}}",
        container,
        capture_stdout=True,
    )
    if rc != 0:
        return False
    text = out.decode("utf-8", errors="replace")
    return "true" in text or "NET_ADMIN" in text


async def _ensure_torrc(container: str):
    """Append required Tor directives to /etc/tor/torrc if missing."""
    _, existing = await _run_cmd(
        "docker", "exec", container, "cat", "/etc/tor/torrc",
        capture_stdout=True,
    )
    torrc = existing.decode("utf-8", errors="replace")

    directives = [
        "TransPort 9040",
        "DNSPort 5353",
        "VirtualAddrNetworkIPv4 10.192.0.0/10",
        "AutomapHostsOnResolve 1",
    ]
    for d in directives:
        if d not in torrc:
            await _run_cmd(
                "docker", "exec", container,
                "sh", "-c", f"echo '{d}' >> /etc/tor/torrc",
            )


async def _wait_tor_ready(container: str, timeout: int = 15) -> bool:
    """Wait for Tor TransPort (9040) to start listening."""
    for _ in range(timeout):
        rc, out = await _run_cmd(
            "docker", "exec", container, "ss", "-tln",
            capture_stdout=True,
        )
        if rc != 0:
            # ss not available, try netstat
            rc, out = await _run_cmd(
                "docker", "exec", container, "netstat", "-tln",
                capture_stdout=True,
            )
        text = out.decode("utf-8", errors="replace")
        if ":9040" in text:
            return True
        await asyncio.sleep(1)
    return False


async def _iptables_has_redirect(container: str) -> tuple[bool, bool]:
    """Check if iptables nat OUTPUT has tcp→9040 and udp→5353 redirects."""
    rc, out = await _run_cmd(
        "docker", "exec", container, "iptables", "-t", "nat", "-L", "OUTPUT", "-n",
        capture_stdout=True,
    )
    text = out.decode("utf-8", errors="replace")
    has_tcp = "REDIRECT" in text and "9040" in text
    has_dns = "REDIRECT" in text and "5353" in text
    return has_tcp, has_dns


async def _iptables_has_killswitch(container: str) -> bool:
    """Check if filter OUTPUT has the REJECT kill-switch rule."""
    rc, out = await _run_cmd(
        "docker", "exec", container, "iptables", "-L", "OUTPUT", "-n",
        capture_stdout=True,
    )
    text = out.decode("utf-8", errors="replace")
    return "REJECT" in text and "tcp" in text


# Per-container Tor PID storage
_tor_pids: dict[str, int] = {}


async def _kill_tor(container: str):
    """Kill any tor processes in the container and clear stored PID."""
    pid = _tor_pids.pop(container, None)
    if pid:
        await _run_cmd("docker", "exec", container, "kill", "-9", str(pid))
    # Also kill any strays
    await _run_cmd("docker", "exec", container, "pkill", "-9", "tor")


async def _tor_rollback(container: str):
    """Undo tor setup: flush iptables (nat + filter), kill tor, re-enable IPv6."""
    await _run_cmd("docker", "exec", container, "iptables", "-t", "nat", "-F")
    await _run_cmd("docker", "exec", container, "iptables", "-F", "OUTPUT")
    await _kill_tor(container)
    await _run_cmd(
        "docker", "exec", container,
        "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0",
    )
    await _run_cmd(
        "docker", "exec", container,
        "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0",
    )


async def tor_start(container: str) -> dict:
    """Start Tor and configure transparent proxy. Rolls back on failure."""
    # 1. Check capabilities
    if not await _check_net_admin(container):
        return {"error": "NET_ADMIN capability required"}

    # 2. Kill any existing tor processes
    await _kill_tor(container)

    # 3. Disable IPv6
    await _run_cmd(
        "docker", "exec", container,
        "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1",
    )
    await _run_cmd(
        "docker", "exec", container,
        "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1",
    )

    # 4. Ensure torrc has required directives
    await _ensure_torrc(container)

    # 5. Start tor directly and capture PID
    # Must use bash -c with double quotes so $! expands to the background PID
    rc, out = await _run_cmd(
        "docker", "exec", container,
        "bash", "-c", "tor >/dev/null 2>&1 & echo $!",
        capture_stdout=True,
    )
    if rc != 0:
        await _tor_rollback(container)
        return {"error": "Failed to start tor process"}

    pid_str = out.decode("utf-8", errors="replace").strip()
    try:
        _tor_pids[container] = int(pid_str)
    except ValueError:
        await _tor_rollback(container)
        return {"error": f"Failed to capture tor PID: {pid_str}"}

    # 6. Wait for tor to be ready
    if not await _wait_tor_ready(container):
        await _tor_rollback(container)
        return {"error": "Tor failed to start (TransPort 9040 not listening after 15s)"}

    # 7. Configure iptables
    has_tcp, has_dns = await _iptables_has_redirect(container)
    if has_tcp or has_dns:
        await _run_cmd("docker", "exec", container, "iptables", "-t", "nat", "-F")

    # nat rules: redirect traffic through Tor
    nat_rules = [
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "debian-tor", "-j", "RETURN"],
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-d", "127.0.0.1/8", "-j", "RETURN"],
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", "9040"],
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"],
    ]
    for rule in nat_rules:
        await _run_cmd("docker", "exec", container, *rule)

    # Kill-switch: if Tor dies, block clearnet leaks
    await _run_cmd("docker", "exec", container, "iptables", "-F", "OUTPUT")
    killswitch_rules = [
        ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "debian-tor", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-d", "127.0.0.1/8", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j", "REJECT"],
    ]
    for rule in killswitch_rules:
        await _run_cmd("docker", "exec", container, *rule)

    # 8. Verify
    has_tcp, has_dns = await _iptables_has_redirect(container)
    has_ks = await _iptables_has_killswitch(container)
    if not has_tcp or not has_dns or not has_ks:
        await _tor_rollback(container)
        return {"error": "iptables rules failed to apply"}

    return {"running": True, "transparent_proxy": True, "kill_switch": True}


async def tor_stop(container: str) -> dict:
    """Stop Tor and remove transparent proxy + kill-switch rules."""
    await _run_cmd("docker", "exec", container, "iptables", "-t", "nat", "-F")
    await _run_cmd("docker", "exec", container, "iptables", "-F", "OUTPUT")
    await _kill_tor(container)
    await _run_cmd(
        "docker", "exec", container,
        "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0",
    )
    await _run_cmd(
        "docker", "exec", container,
        "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0",
    )
    return {"running": False, "transparent_proxy": False, "kill_switch": False}


async def tor_status(container: str) -> dict:
    """Check if Tor is running with transparent proxy and kill-switch active."""
    running = False
    pid = _tor_pids.get(container)
    if pid:
        # Check if stored PID is still alive
        rc, _ = await _run_cmd(
            "docker", "exec", container, "kill", "-0", str(pid),
            capture_stdout=True,
        )
        if rc == 0:
            running = True
        else:
            # PID is dead, clean up
            _tor_pids.pop(container, None)
    has_tcp, has_dns = await _iptables_has_redirect(container)
    has_ks = await _iptables_has_killswitch(container)
    transparent_proxy = running and has_tcp and has_dns
    return {"running": running, "transparent_proxy": transparent_proxy, "kill_switch": has_ks}
