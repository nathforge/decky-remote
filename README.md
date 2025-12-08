# Decky Remote

Development tool for Decky plugins.

## Features

 1. Tail logs: `decky-remote plugin logs "Example Plugin"`
 2. Call Decky websocket methods:
    * Reload plugin: `decky-remote ws call loader/reload_plugin "Example Plugin"`
    * Call plugin function: `decky-remote ws call loader/call_plugin_method "Example Plugin" start_timer`
    * (See [the Decky Loader source](https://github.com/search?q=repo%3ASteamDeckHomebrew%2Fdecky-loader%20ws.add_route&type=code) for available routes.)

## Usage

 * uv: `uvx decky-remote ssh utilities/ping`
 * Python: clone this repo then `python -m pip install .`. `decky-remote` is now available.

## Development

 * `uv sync`
 * `python src/decky_remote [...]`

Creating a release: `TAG=vX.Y.Z && git tag $TAG && git push origin $TAG`
