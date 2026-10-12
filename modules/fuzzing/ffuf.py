"""
Wrapper for ffuf (content/directory fuzzing). Tier 2.

CLI: ffuf -u <asset>/FUZZ -w <wordlist> -of json -o <output_path> -rate <rps>

TODO: implement FfufModule(ToolModule) -- run() shells out (respecting
config.tiers.tier2.rate_limit_rps), parse() reads the JSON report and
returns list[Finding] for interesting status codes (200/301/403/500 by
default, configurable).
"""
