"""
Wrapper for Arjun (hidden HTTP parameter discovery). Tier 2.

CLI: arjun -u <asset> -oJ <output_path>

TODO: implement ArjunModule(ToolModule) -- run() shells out, parse() reads
the JSON output and returns list[Asset] -- discovered parameters feed into
other Tier 2 modules (ffuf, dalfox) as additional attack surface, so this
module's output type is Asset, not Finding.
"""
