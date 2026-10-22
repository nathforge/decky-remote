def decky_protontricks_run(appid: int, args: list[str], timeout: float = 170.0) -> dict:
    """
    Run `protontricks <appid> <args...>` (e.g. a winetricks verb like
    `vcrun2022`, or `-c "<command>"`) against the Deck's actual gamescope
    session, returning `{"returncode", "stdout", "stderr"}`.

    This needs a real display: Wine's install bootstraps (e.g. the official
    `vc_redist.x64.exe` invoked by `winetricks vcrunXXXX`) create a window
    even when run "quiet", and without a working graphics driver they abort
    with `nodrv_CreateWindow` / "no driver could be loaded" - confirmed
    on-device, running via a bare SSH shell with no DISPLAY set. A plain SSH
    session has no graphical session attached at all (no DISPLAY,
    WAYLAND_DISPLAY, or XDG_RUNTIME_DIR pointing anywhere useful), so this
    reads `/run/user/<uid>/gamescope-environment` - the actual environment
    gamescope's own session exports for itself - and overlays it on top of
    this process's environment before running anything. Confirmed on-device:
    that file sets `DISPLAY=:0` (gamescope's session is `XDG_SESSION_TYPE=x11`
    - Xwayland, not raw Wayland - `GAMESCOPE_WAYLAND_DISPLAY` exists but isn't
    the thing Wine's driver probe actually needs here).

    A silent DLL-extraction-only installer (e.g. the "AIO" vcredist tools)
    doesn't need any of this and will "succeed" even headless - but it also
    never performs a real install transaction, so it won't satisfy a game's
    own dependency check that looks for the real installer's registry
    footprint (`HKLM\\SOFTWARE\\Classes\\Installer\\Dependencies`), even
    though the runtime DLLs it drops are perfectly functional. Confirmed
    on-device against Dead as Disco (Clickteam-style dependency-checker
    dialog persisted after an AIO-tool install despite correct DLLs and
    `VisualStudio\\14.0\\VC\\Runtimes` registry keys both being present).

    This function can be sent to the Deck over SSH, so must be completely
    self-contained.
    """

    import os
    import subprocess

    def session_env() -> dict[str, str]:
        env = dict(os.environ)
        runtime_dir = env.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
        env_file = os.path.join(runtime_dir, "gamescope-environment")
        try:
            with open(env_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    env[key] = value
        except OSError:
            pass
        env.setdefault("XDG_RUNTIME_DIR", runtime_dir)
        return env

    cmd = ["flatpak", "run", "com.github.Matoking.protontricks", str(appid), *args]
    result = subprocess.run(
        cmd,
        env=session_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "returncode": result.returncode,
        # Trimmed: Wine's own debug-channel noise can run to tens of
        # thousands of lines; the tail is what actually matters for a
        # pass/fail readout.
        "stdout": result.stdout[-20000:],
        "stderr": result.stderr[-20000:],
    }
