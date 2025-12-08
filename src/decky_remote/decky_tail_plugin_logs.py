def decky_tail_plugin_logs(plugin_name: str):
    """
    Tail a plugin's logs, watching for new log files.

    This function is sent to the Deck over SSH, so must be completely
    self-contained.
    """

    import subprocess
    import sys
    import time
    from pathlib import Path

    dir_poll_interval_secs = 0.25
    tail_terminate_timeout_secs = 2

    def iterdir_ignoring_missing_dir(path: Path):
        try:
            yield from path.iterdir()
        except FileNotFoundError:
            pass

    log_root = Path("homebrew/logs")

    log_paths = (
        # Original plugin name
        log_root / plugin_name,
        # "decky plugin build" replaces " " with "-"
        log_root / plugin_name.replace(" ", "-"),
    )

    first_loop = True
    log_file: None | Path = None
    tail_process: None | subprocess.Popen[bytes] = None
    while True:
        try:
            latest_file = max(
                (
                    file
                    for log_path in log_paths
                    for file in iterdir_ignoring_missing_dir(log_path)
                ),
                key=lambda file: file.stat().st_mtime,
            )
        except ValueError:
            latest_file = None

        # Check if the latest file has changed, or it's the first loop.
        # (We only track the first loop to show "Waiting for a log file" -
        # otherwise on the first loop `latest_file == log_file == None`,
        # and the below logic wouldn't trigger.)
        if latest_file != log_file or first_loop:
            if tail_process:
                try:
                    tail_process.terminate()
                    _ = tail_process.wait(timeout=tail_terminate_timeout_secs)
                except Exception:
                    tail_process.kill()
                tail_process = None

            if latest_file:
                print(f"\033[33mTailing {latest_file}\033[m", file=sys.stderr)
                tail_process = subprocess.Popen(["tail", "-f", str(latest_file)])
            else:
                print("\033[33mWaiting for a log file\033[m", file=sys.stderr)

        first_loop = False
        log_file = latest_file
        time.sleep(dir_poll_interval_secs)
