"""
Decky Remote.

 * Tails plugin logs:
   * `decky-remote plugin logs "Example Plugin"`
 * Calls Decky Loader websocket routes:
   * `decky-remote ws call utilities/ping`
   * `decky-remote ws call loader/reload_plugin "Example Plugin"`
   * `decky-remote ws call loader/call_plugin_method "Example Plugin" start_timer`
"""

import json
from importlib.metadata import version as get_version
from typing import Annotated, Any, Callable, Literal

import typer

from decky_remote.decky_tail_plugin_logs import decky_tail_plugin_logs
from decky_remote.decky_ws_request import decky_ws_request
from decky_remote.ssh_rpc import make_ssh_rpc

app = typer.Typer()
ws_app = typer.Typer()
plugin_app = typer.Typer()

app.add_typer(ws_app, name="ws")
app.add_typer(plugin_app, name="plugin")

default_ssh = "deck@steamdeck.local"
default_ws_url = "http://localhost:1337"

SshDestination = Annotated[str, typer.Option(help="SSH user@host")]
WsUrl = Annotated[str, typer.Option(help="Decky Loader URL")]


def main():
    try:
        app()
    except KeyboardInterrupt:
        return


@app.command()
def version() -> None:
    """Show version"""
    try:
        pkg_version = get_version("decky-remote")
        typer.echo(pkg_version)
    except Exception:
        typer.echo("unknown")


@ws_app.command()
def call(
    route: str,
    args: Annotated[list[str] | None, typer.Argument()] = None,
    transport: Annotated[Literal["ssh", "http"], typer.Option()] = "ssh",
    destination: SshDestination = default_ssh,
    url: WsUrl = default_ws_url,
) -> None:
    """Execute websocket call"""
    if args is None:
        args = []

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
        raise typer.BadParameter("Unexpected transport")

    req_message = {
        "type": 0,
        "id": 0,
        "route": route,
        "args": args,
    }

    res_message = ws_request(url, req_message)

    if res_message is None:
        raise typer.Exit(code=1)

    if res_message["type"] == 1:  # Reply
        typer.echo(json.dumps(res_message["result"]))
        return

    if res_message["type"] == -1:  # Error
        raise typer.Exit(code=1)

    raise typer.Exit(code=1)


@plugin_app.command()
def logs(
    plugin_name: str,
    destination: SshDestination = default_ssh,
) -> None:
    """Tail plugin logs"""
    ssh_rpc_decky_tail_plugin_logs = make_ssh_rpc(
        destination,
        decky_tail_plugin_logs,
        capture_stdout=False,
    )

    ssh_rpc_decky_tail_plugin_logs(plugin_name)
