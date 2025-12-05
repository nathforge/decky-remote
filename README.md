# Decky Remote

I wrote this to quickly reload [Decky Loader](https://github.com/SteamDeckHomebrew/decky-loader) plugins, e.g:

```shell
$ decky-remote.py ssh loader/reload_plugin "Example Plugin"
```

However it can call any Decky Loader websocket route, e.g:

```shell
$ decky-remote.py ssh utilities/ping
$ decky-remote.py ssh loader/call_plugin_method "Example Plugin" start_timer
```

⚠️ This is a development tool that can break at any point. It is not part of Decky.

See [the Decky Loader source](https://github.com/search?q=repo%3ASteamDeckHomebrew%2Fdecky-loader%20add_route&type=code) for available routes.

## How does it work?

Decky Loader runs an HTTP server on http://localhost:1337. We connect to the
Deck over SSH and call the HTTP server.
