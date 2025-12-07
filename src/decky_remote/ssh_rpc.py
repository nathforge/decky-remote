import inspect
import json
import subprocess
from typing import Callable


def make_ssh_rpc(
    destination: str,
    func: Callable,
    capture_stdout,
):
    """
    Run a Python function on a remote machine via SSH.

    The function must be self-contained and return a JSON-encodable result.
    """

    def ssh_rpc(*args, **kwargs):
        script = (
            f"import json\n"
            f"{inspect.getsource(func)}\n"
            f"result = {func.__name__}(*{repr(args)}, **{repr(kwargs)})\n"
            f"print(json.dumps(result))"
        )

        cmd = ["ssh", "--", destination, "python3"]

        result = subprocess.run(
            cmd,
            input=script,
            capture_output=capture_stdout,
            text=True,
        )

        if result.returncode != 0:
            raise Exception(result.stderr)

        if capture_stdout:
            return json.loads(result.stdout)

    return ssh_rpc
