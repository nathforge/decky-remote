"""
Decky Remote.

Calls Decky Loader websocket routes over SSH, e.g:

    $ decky-remote ssh utilities/ping
    $ decky-remote ssh loader/reload_plugin "Example Plugin"
    $ decky-remote ssh loader/call_plugin_method "Example Plugin" start_timer

Tails plugin logs:

    $ decky-remote plugin logs "Example Plugin"
"""

import argparse
import json
from typing import Any, Callable

from decky_remote.decky_tail_plugin_logs import decky_tail_plugin_logs
from decky_remote.decky_ws_request import decky_ws_request
from decky_remote.ssh_rpc import make_ssh_rpc


def main():
    parser = argparse.ArgumentParser(prog="decky-remote")

    subparsers = parser.add_subparsers(dest="command", required=True)

    ssh_parser = subparsers.add_parser("ssh", help="Execute call over SSH")
    ssh_parser.add_argument(
        "--destination",
        default="deck@steamdeck.local",
        help="Destination user@host (default: deck@steamdeck.local)",
    )
    ssh_parser.add_argument(
        "--url",
        default="http://localhost:1337",
        help="Decky Loader URL (default: http://localhost:1337)",
    )
    ssh_parser.add_argument("route", help="Route to call")
    ssh_parser.add_argument("args", help="Route arguments", nargs="*")
    ssh_parser.set_defaults(func=cmd_ssh)

    http_parser = subparsers.add_parser("http", help="Execute call over HTTP")
    http_parser.add_argument(
        "--url",
        default="http://localhost:1337",
        help="Decky Loader URL (default: http://localhost:1337)",
    )
    http_parser.add_argument("route", help="Route to call")
    http_parser.add_argument("args", help="Route arguments", nargs="*")
    http_parser.set_defaults(func=cmd_http)

    plugin_parser = subparsers.add_parser("plugin")
    plugin_subparsers = plugin_parser.add_subparsers(
        dest="plugin_command", required=True
    )

    plugin_logs_parser = plugin_subparsers.add_parser("logs")
    plugin_logs_parser.add_argument(
        "--destination",
        default="deck@steamdeck.local",
        help="Destination user@host (default: deck@steamdeck.local)",
    )
    plugin_logs_parser.add_argument("plugin_name", help="Plugin name")
    plugin_logs_parser.set_defaults(func=cmd_plugin_logs)

    args = parser.parse_args()

    try:
        run_command(args)
    except KeyboardInterrupt:
        return


def run_command(args):
    if args.func is cmd_ssh:
        return cmd_ssh(args.destination, args.url, args.route, args.args)

    if args.func is cmd_http:
        return cmd_http(args.url, args.route, args.args)

    if args.func is cmd_plugin_logs:
        return cmd_plugin_logs(args.destination, args.plugin_name)

    raise Exception("Unimplemented command")


def cmd_ssh(
    destination: str,
    url: str,
    route: str,
    args: list[str],
) -> None:
    ssh_rpc_decky_ws_request = make_ssh_rpc(
        destination,
        decky_ws_request,
        capture_stdout=True,
    )
    _cmd_decky_ws_request(
        lambda body: ssh_rpc_decky_ws_request(url, body),
        route,
        args,
    )


def cmd_http(url: str, route: str, args: list[str]) -> None:
    _cmd_decky_ws_request(
        lambda body: decky_ws_request(url, body),
        route,
        args,
    )


def cmd_plugin_logs(destination: str, plugin_name: str) -> None:
    ssh_rpc_decky_tail_plugin_logs = make_ssh_rpc(
        destination,
        decky_tail_plugin_logs,
        capture_stdout=False,
    )
    ssh_rpc_decky_tail_plugin_logs(plugin_name)


def _cmd_decky_ws_request(
    request: Callable[[dict], Any],
    route: str,
    args: list[str],
) -> None:
    """
    Make a request and print the result.
    """

    req_message = {
        "type": 0,
        "id": 0,
        "route": route,
        "args": args,
    }

    res_message = request(req_message)

    if res_message["type"] == 1:  # Reply
        print(json.dumps(res_message["result"]))
        return

    if res_message["type"] == -1:  # Error
        raise Exception(res_message["error"])

    raise Exception(f"Unknown type in {res_message}")
