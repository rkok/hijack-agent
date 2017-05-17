Hijack agent for TCP connections
================================

Sniffs traffic on an interface and triggers an action when packets match user-defined rules.

Usage
-----

1. `cp match.dist.py match.py` and configure your desired packet matching rules
2. `cp hijack.dist.py hijack.py` and configure your desired action
3. `./agent.py <listen interface> [action wait seconds]`

Works well in combination with [bridge-mitm-tools](https://github.com/rkok/bridge-mitm-tools)!

Example usage
-------------

Listen on interface __br0__ and run _<action>_ after __5__ seconds of silence:

`./agent.py br0 5`

This will:

1. Monitor __br0__ for incoming and outgoing packets
2. Attempt to detect a client packet using `match.py:match_client()`
3. On client detection, attempt to detect a server packet using `match.py:match_server()`
4. On client and server detection, wait __5__ (default: 3) seconds
5. Trigger `hijack.py:start_hijack()`
6. On interrupt (CTRL-C), trigger `hijack.py:stop_hijack()`

See also: `*.example.py`.
