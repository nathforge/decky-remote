def decky_gamescope_screenshot(timeout: float = 5.0) -> str:
    """
    Capture gamescope's actual composited output, returning base64-encoded
    PNG data.

    Unlike `cef screenshot` (Chrome DevTools Protocol against a single CEF
    tab), this uses gamescope's own `gamescopectl screenshot <path>` debug
    command, so it captures the real on-screen frame - a running game, not
    just Steam's own UI layer.

    `gamescopectl screenshot` is not reliably synchronous even when given an
    explicit output path: a call can return success (exit 0) with no file
    ever appearing, confirmed on-device. So this polls for the file to show
    up and its size to stop changing, retrying the whole command on timeout
    rather than trusting a single call.

    This function can be sent to the Deck over SSH, so must be completely
    self-contained.
    """

    import base64
    import os
    import subprocess
    import tempfile
    import time

    env = dict(os.environ)
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")

    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = os.path.join(tmp_dir, "screenshot.png")
        deadline = time.monotonic() + timeout
        last_error = ""

        while time.monotonic() < deadline:
            result = subprocess.run(
                ["gamescopectl", "screenshot", out_path],
                env=env,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                last_error = (result.stderr or result.stdout).strip()
            elif os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
                first_size = os.path.getsize(out_path)
                time.sleep(0.2)
                if os.path.isfile(out_path) and os.path.getsize(out_path) == first_size:
                    with open(out_path, "rb") as f:
                        return base64.b64encode(f.read()).decode("ascii")

            time.sleep(0.3)

        detail = f" (last error: {last_error})" if last_error else ""
        raise Exception(f"gamescopectl screenshot produced no file within {timeout}s{detail}")
