# Decky Remote

Development tool for Decky plugins.

## Features

 1. Tail logs: `decky-remote.py plugin logs "Example Plugin"`
 2. Call Decky websocket methods:
    * Reload plugin: `decky-remote.py ssh loader/reload_plugin "Example Plugin"`
    * Call plugin function: `decky-remote.py ssh loader/call_plugin_method "Example Plugin" start_timer`
    * (See [the Decky Loader source](https://github.com/search?q=repo%3ASteamDeckHomebrew%2Fdecky-loader%20ws.add_route&type=code) for available routes.)

⚠️ This is a development tool that can break at any point. It is not part of Decky.
