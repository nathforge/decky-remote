"""
Decky Remote.

 * Tails plugin logs:
   * `decky-remote plugin logs "Example Plugin"`
 * Calls Decky Loader websocket routes:
   * `decky-remote ws call utilities/ping`
   * `decky-remote ws call loader/reload_plugin "Example Plugin"`
   * `decky-remote ws call loader/call_plugin_method "Example Plugin" start_timer`
"""

import argparse
import json
from typing import Any, Callable, Literal, cast

from decky_remote.decky_tail_plugin_logs import decky_tail_plugin_logs
from decky_remote.decky_ws_request import decky_ws_request
from decky_remote.ssh_rpc import make_ssh_rpc


def main():
    parser = argparse.ArgumentParser(prog="decky-remote")

    subparsers = parser.add_subparsers(dest="command", required=True)

    ws_parser = subparsers.add_parser("ws")
    ws_subparsers = ws_parser.add_subparsers(dest="ws_command", required=True)

    ws_call_parser = ws_subparsers.add_parser("call", help="Execute websocket call")
    _ = ws_call_parser.add_argument(
        "--transport", default="ssh", choices=("ssh", "http")
    )
    _ = ws_call_parser.add_argument(
        "--destination",
        default="deck@steamdeck.local",
        help="Destination user@host (default: deck@steamdeck.local)",
    )
    _ = ws_call_parser.add_argument(
        "--url",
        default="http://localhost:1337",
        help="Decky Loader URL (default: http://localhost:1337)",
    )
    _ = ws_call_parser.add_argument("route", help="Route to call")
    _ = ws_call_parser.add_argument("args", help="Route arguments", nargs="*")
    ws_call_parser.set_defaults(func=cmd_ws_call)

    plugin_parser = subparsers.add_parser("plugin")
    plugin_subparsers = plugin_parser.add_subparsers(
        dest="plugin_command", required=True
    )

    plugin_logs_parser = plugin_subparsers.add_parser("logs")
    _ = plugin_logs_parser.add_argument(
        "--destination",
        default="deck@steamdeck.local",
        help="Destination user@host (default: deck@steamdeck.local)",
    )
    _ = plugin_logs_parser.add_argument("plugin_name", help="Plugin name")
    plugin_logs_parser.set_defaults(func=cmd_plugin_logs)

    args = parser.parse_args()

    try:
        run_command(args)
    except KeyboardInterrupt:
        return


def run_command(args):
    if args.func is cmd_ws_call:
        return cmd_ws_call(
            cast(Literal["ssh"] | Literal["http"], args.transport),
            cast(str, args.destination),
            cast(str, args.url),
            cast(str, args.route),
            cast(list[str], args.args),
        )

    if args.func is cmd_plugin_logs:
        return cmd_plugin_logs(
            cast(str, args.destination),
            cast(str, args.plugin_name),
        )

    raise Exception("Unimplemented command")


def cmd_ws_call(
    transport: Literal["ssh"] | Literal["http"],
    destination: str,
    url: str,
    route: str,
    args: list[str],
) -> None:
    ws_request: Callable[[str, dict[str, Any]], None | dict[str, Any]]

    if transport == "ssh":
        ws_request = make_ssh_rpc(
            destination,
            decky_ws_request,
            capture_stdout=True,
        )
    elif transport == "http":
        ws_request = decky_ws_request
    else:
        raise Exception("Unexpected transport")

    req_message = {
        "type": 0,
        "id": 0,
        "route": route,
        "args": args,
    }

    res_message = ws_request(url, req_message)

    if res_message is None:
        raise Exception("Websocket closed before receiving a response")

    if res_message["type"] == 1:  # Reply
        print(json.dumps(res_message["result"]))
        return

    if res_message["type"] == -1:  # Error
        raise Exception(res_message["error"])

    raise Exception(f"Unexpected type in {res_message}")


def cmd_plugin_logs(destination: str, plugin_name: str) -> None:
    ssh_rpc_decky_tail_plugin_logs = make_ssh_rpc(
        destination,
        decky_tail_plugin_logs,
        capture_stdout=False,
    )

    ssh_rpc_decky_tail_plugin_logs(plugin_name)
