# Decky Remote

Development tool for Decky plugins.

## Features

 1. Tail logs: `decky-remote plugin logs "Example Plugin"`
 2. Call Decky websocket methods:
    * Reload plugin: `decky-remote ws call loader/reload_plugin "Example Plugin"`
    * Call plugin function: `decky-remote ws call loader/call_plugin_method "Example Plugin" start_timer`
    * Arguments are parsed as JSON where possible, so `true`/`123`/`{"a": 1}` reach the route as real types, not strings.
    * (See [the Decky Loader source](https://github.com/search?q=repo%3ASteamDeckHomebrew%2Fdecky-loader%20ws.add_route&type=code) for available routes.)
 3. Run JS live in a CEF tab (default: `SharedJSContext`, where `window.SteamClient`/`window.DFL` live):
    * `decky-remote cef eval "1 + 1"`
    * `decky-remote cef eval --tab QuickAccess "document.title"`
    * This is the same remote-debugging mechanism as `chrome://inspect`, just from the command line. Decky's "Allow Remote CEF Debugging" setting is *not* required for this (it only gates direct CDP access).
 4. Inject/remove CSS live into a CEF tab:
    * `decky-remote cef css-inject "body { background: red; }"` (prints a css id)
    * `decky-remote cef css-remove <css-id>`

## Usage

 * uv: `uvx decky-remote`
 * pip: `pip install decky-remote`. `decky-remote` is now available.

## Development

 * `uv run decky-remote`

Creating a release: `TAG=vX.Y.Z && git tag $TAG && git push origin $TAG`
