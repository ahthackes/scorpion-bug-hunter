# Base image with the Phase 1 tool chain preinstalled.
# Built out incrementally as modules/ gets implemented -- keep this in sync
# with whatever tools core/pipeline/*.py actually shells out to.

FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    golang-go \
    cargo \
    git curl wget \
    nmap \
    massdns \
    feroxbuster \
    && rm -rf /var/lib/apt/lists/*

# Go-based recon tools (Phase 1 set) -- installed via `go install`, binaries
# land in $GOPATH/bin, which must be on PATH.
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin

# Tier 0 (passive recon)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/gwen001/github-subdomains@latest && \
    go install -v github.com/gwen001/gitlab-subdomains@latest && \
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest && \
    go install -v github.com/glebarez/cero@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest

# Tier 0 (passive recon) -- second batch, added when every "add all the
# tools" suggestion was implemented: amass (active+passive subdomain
# enum, run here in -passive mode), tlsx (cert SAN/CN scraping),
# asnmap (ASN -> CIDR lookup, feeds IP_RANGE assets).
RUN go install -v github.com/owasp-amass/amass/v4/cmd/amass@master && \
    go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
    go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest

# cloud_enum (cloud storage bucket enumeration, feeds BUCKET assets) and
# GitDorker (GitHub code-search dorking, needs GITHUB_TOKEN at runtime) --
# both single-script Python tools with no pip package, wrapped the same
# way Corsy/OpenRedireX/smuggler/SSRFmap are below.
RUN git clone --depth 1 https://github.com/initstring/cloud_enum /opt/tools/cloud_enum && \
    pip3 install --break-system-packages -r /opt/tools/cloud_enum/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/tools/cloud_enum/cloud_enum.py "$@"\n' > /usr/local/bin/cloud_enum.py && \
    chmod +x /usr/local/bin/cloud_enum.py && \
    git clone --depth 1 https://github.com/obheda12/GitDorker /opt/tools/gitdorker && \
    pip3 install --break-system-packages -r /opt/tools/gitdorker/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/tools/gitdorker/GitDorker.py "$@"\n' > /usr/local/bin/GitDorker.py && \
    chmod +x /usr/local/bin/GitDorker.py

# Tier 1 (active, non-intrusive)
# nmap and massdns come from apt above (massdns is puredns's resolution
# backend, used as a library binary rather than invoked directly).
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/sensepost/gowitness@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/PentestPad/subzy@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest && \
    go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
RUN webanalyze -update || true
RUN pip3 install --break-system-packages wafw00f

# Tier 1 second batch -- shuffledns (bulk DNS resolve, reuses puredns's
# massdns/resolvers.txt setup), cdncheck and dnsReaper (ProjectDiscovery
# Go tools), s3scanner (bucket permission probing, consumes cloud_enum's
# BUCKET assets), whatweb (Kali-packaged Ruby tool), dnstwist
# (typosquat/permutation scanner, pip package).
RUN go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest && \
    go install -v github.com/sa7mon/s3scanner@latest
RUN apt-get update && apt-get install -y whatweb && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages dnstwist
RUN git clone --depth 1 https://github.com/punk-security/dnsReaper /opt/tools/dnsreaper && \
    pip3 install --break-system-packages -r /opt/tools/dnsreaper/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/tools/dnsreaper/main.py "$@"\n' > /usr/local/bin/dnsreaper && \
    chmod +x /usr/local/bin/dnsreaper
# git-exposure (modules/vuln/git_exposure.py) is a native curl-based check
# -- no separate binary to install here, same as core/url_tools.py's
# pure-Python fallbacks.

# Tier 2 batch 1 (parameter + content discovery)
# feroxbuster comes from apt above (it's packaged in Kali). x8 is Rust --
# cargo (from apt above) builds it; ~/.cargo/bin must be on PATH.
ENV PATH=$PATH:/root/.cargo/bin
RUN go install -v github.com/ffuf/ffuf/v2@latest && \
    cargo install x8 && \
    pip3 install --break-system-packages arjun

# Tier 2 content-discovery/crawling second batch: kiterunner (API route
# brute-forcing, binary is "kr"; built from source since it isn't a plain
# `go install`-able module), gospider and cariddi (JS-aware crawlers),
# xnLinkFinder (endpoint/parameter extraction, fetches the URL directly).
RUN git clone --depth 1 https://github.com/assetnote/kiterunner /opt/tools/kiterunner && \
    cd /opt/tools/kiterunner && make build && cp ./dist/kr /usr/local/bin/kr && cd /
RUN go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest
RUN pip3 install --break-system-packages xnLinkFinder && \
    printf '#!/bin/sh\nexec xnLinkFinder "$@"\n' > /usr/local/bin/xnLinkFinder.py && \
    chmod +x /usr/local/bin/xnLinkFinder.py

# Tier 2 glue utilities (anew, gf, qsreplace, unfurl, uro, kxss) -- each
# has a pure-Python fallback in core/url_tools.py too, so these are a
# nice-to-have for exact upstream behavior, not a hard requirement.
RUN go install -v github.com/tomnomnom/anew@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/tomnomnom/unfurl@latest && \
    go install -v github.com/Emoe/kxss@latest && \
    pip3 install --break-system-packages uro
# gf's pattern library (what "-xss", "-ssrf", etc actually match) isn't
# bundled with the binary -- it's a separate community repo of regexes.
RUN mkdir -p /root/.gf && \
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns && \
    cp /tmp/gf-patterns/*.json /root/.gf/ && \
    rm -rf /tmp/gf-patterns

# Tier 2 batch 2 (vuln-class scanners)
# wpscan ships in Kali's repos (it's a Ruby gem with a lot of native
# deps -- apt is far simpler than a manual gem install here).
RUN apt-get update && apt-get install -y wpscan && rm -rf /var/lib/apt/lists/*
RUN go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
# Corsy, OpenRedireX, smuggler and SSRFmap are single-script tools with
# no Go/pip package -- clone each and wrap it in a thin shell script on
# PATH so modules/vuln/*.py's run_command(["corsy", ...]) etc. just work.
RUN mkdir -p /opt/tools && \
    git clone --depth 1 https://github.com/s0md3v/Corsy /opt/tools/corsy && \
    pip3 install --break-system-packages -r /opt/tools/corsy/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/tools/corsy/corsy.py "$@"\n' > /usr/local/bin/corsy && \
    chmod +x /usr/local/bin/corsy && \
    git clone --depth 1 https://github.com/devanshbatham/OpenRedireX /opt/tools/openredirex && \
    printf '#!/bin/sh\nexec python3 /opt/tools/openredirex/openredirex.py "$@"\n' > /usr/local/bin/openredirex && \
    chmod +x /usr/local/bin/openredirex && \
    git clone --depth 1 https://github.com/defparam/smuggler /opt/tools/smuggler && \
    printf '#!/bin/sh\nexec python3 /opt/tools/smuggler/smuggler.py "$@"\n' > /usr/local/bin/smuggler && \
    chmod +x /usr/local/bin/smuggler && \
    git clone --depth 1 https://github.com/swisskyrepo/SSRFmap /opt/tools/ssrfmap && \
    pip3 install --break-system-packages -r /opt/tools/ssrfmap/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/tools/ssrfmap/ssrfmap.py "$@"\n' > /usr/local/bin/ssrfmap && \
    chmod +x /usr/local/bin/ssrfmap

# testssl.sh (deep TLS/cipher audit, pure shell+openssl, no build step)
# and graphql-cop (GraphQL-specific misconfig scanner, pip package).
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/tools/testssl && \
    printf '#!/bin/sh\nexec /opt/tools/testssl/testssl.sh "$@"\n' > /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh
RUN pip3 install --break-system-packages graphql-cop

# Secrets scanning (operate on repo URLs/paths, not auto-wired per-target yet)
RUN go install -v github.com/trufflesecurity/trufflehog/v3@latest && \
    go install -v github.com/gitleaks/gitleaks/v8@latest

# Scope-ingestion tools (bbscope: Go; Hacker-Scoper: Python)
RUN go install -v github.com/sw33tLie/bbscope@latest
RUN pip3 install --break-system-packages hackerscoper || true

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

COPY . .

ENTRYPOINT ["python3", "cli.py"]
