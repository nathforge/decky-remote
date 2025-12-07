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

    for basename in (
        plugin_name,  # Original plugin name
        plugin_name.replace(" ", "-"),  # "decky plugin build" replaces " " with "-"
    ):
        log_path = Path("homebrew/logs") / basename
        if log_path.is_dir():
            break
    else:
        raise Exception("Can't find plugin log directory")

    first_loop = True
    log_file: None | Path = None
    tail_process: None | subprocess.Popen = None
    while True:
        try:
            latest_file = max(
                (file for file in log_path.iterdir()),
                key=lambda file: file.stat().st_mtime,
            )
        except ValueError:
            latest_file = None

        if first_loop or latest_file != log_file:
            if tail_process:
                try:
                    tail_process.terminate()
                    tail_process.wait(timeout=tail_terminate_timeout_secs)
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
