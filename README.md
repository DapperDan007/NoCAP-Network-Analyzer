# NoCAP Network Analyzer

NoCAP's web interface is called **PCAP Lens**. This repository contains the Docker app, offline traffic analysis engine, interactive network map, and local indicator-import tooling.

A self-hosted, Dockerized web app for investigating uploaded PCAP and PCAPNG captures. Analysis and storage stay on your server. There is no live packet capture, cloud upload, telemetry, external lookup, or LLM dependency.

## GitHub workflow

Source: [DapperDan007/NoCAP-Network-Analyzer](https://github.com/DapperDan007/NoCAP-Network-Analyzer).

Completed Codex changes in this workspace should be checked, committed, and pushed to this repository as described in `AGENTS.md`. This is a workflow instruction, not a background file-watching sync service. Captures, analysis reports, downloaded indicator files, and `.env` secrets stay local and are excluded from Git. The GitHub Actions workflow runs the container test suite on pushes and pull requests.

## Start

Install Docker Engine + Compose on Linux, or Docker Desktop using Linux containers on Windows/macOS. In this directory:

```sh
docker compose up --build -d
```

Open **http://localhost:8080**, choose a capture, and wait for analysis. Captures exported from pfSense's **Diagnostics → Packet Capture** work with this workflow. Capture on LAN / IoT VLAN interfaces when you want individual device addresses before NAT.

```sh
docker compose logs -f
docker compose down
```

`down` preserves the named `capture-data` volume. Captures, reports, session history, and imported indicators persist there. Delete a session in the UI to remove its capture and report. No automatic expiry is configured.

### Windows startup troubleshooting

If Docker reports it is unable to start and `wsl --version` reports `Wsl/CallMsi/Install/REGDB_E_CLASSNOTREG`, the WSL installation needs repair before container builds will work. Run the Microsoft WSL installer/repair as a Windows administrator, complete any requested restart, and reopen Docker Desktop. Verify with `wsl --version` and `docker version` (both client and server should respond). This is a host setup issue, separate from the application.

## Included analysis

### Interactive network map

Open **Network map** in the sidebar and choose a completed capture. Saved reports work immediately without reanalysis. Private IPv4 addresses are grouped using a selectable /24, /20, or /16 display prefix; ULA IPv6 addresses use /64. These are logical address groups, not detected subnet masks. External/other endpoints start collapsed together; special-use addresses are opt-in.

Double-click a group (or use Expand in the sidebar/inspector) to reveal hosts. Drag nodes to arrange them, drag the background to pan, scroll or use +/− to zoom, and use Fit view to recenter. Select an endpoint to highlight its visible neighbors and inspect communicating peers, direction totals, observed destination ports, names, and packet references. Search by IP or contacted/queried name and select a result to focus its connections. Focus connections narrows the view to a group or endpoint and its direct peers; Show full map clears that focus. Keyboard: Tab to nodes, Enter to inspect, Space to expand a group; on the canvas itself, arrow keys pan, +/− zoom, and Home fits the view.

Links aggregate observed directional flows into unordered endpoint pairs, with both directions counted once. They represent communications, not physical cables, discovered routes, or confirmed service connections. Line width reflects frame bytes. Intra-group flows are available in the group inspector even while the group is collapsed. Endpoint byte totals describe the whole capture; focused links show only the selected conversations. Group byte totals sum member traffic (internal traffic touches two members), while conversation totals count each directional flow once.

For responsiveness, the map displays at most 160 nodes and 500 aggregate links, prioritizing traffic volume; the canvas explicitly reports omissions. Focus a host/group to narrow large maps. The inspector lists its top 80 conversations, and search offers the first 16 matches with the full match count. Full observations remain in report exports and the existing table views. The map uses bundled SVG/JavaScript and makes no external lookups.

- IPv4/IPv6 endpoint inventory, observed MAC addresses, frame-byte counts, and contacted names.
- Directional flows and DNS / visible TLS SNI / HTTP hostname observations.
- Low-confidence Roku / Ring / Sonos ecosystem hints from contacted domains. Other local endpoints are explicitly unidentified.
- Local IP and domain indicator matching with provenance, observation counts, and packet references. Subdomain matching respects DNS label boundaries.
- Possible scanning: 20 distinct target addresses or destination ports in a rolling 60-second window of TCP SYN attempts. Retransmissions excluded where TShark identifies them.
- Periodic outbound SYN attempts: at least 8 observations, mean interval at least 5 seconds, interval coefficient of variation at most 10%. Informational only: ordinary polling is common.
- Repeated NXDOMAIN responses: at least 20 response packets and 10 distinct queried names per recipient.
- TCP connection attempts to Telnet/FTP ports, and visible HTTP Basic authorization. Reports omit credential values; original PCAP files still contain their original bytes.
- Downloadable JSON reports and original captures, filtering, and saved sessions.

These rules produce investigation leads, not confirmed compromise verdicts. There is **no CVE/firmware assessment, exploit-signature engine, verified device fingerprinting, or AI model** in this version. Encrypted content, encrypted DNS, VPNs, absent traffic, and capture placement limit visibility. Public IPv6 endpoints may be LAN devices; address scope does not establish ownership. MAC addresses across routed networks may belong to the next hop. Frame-byte totals are not application upload totals. The Coverage & limits tab records these limitations with every report.

## Local threat intelligence

To download a starter set of Threatview's public high-confidence IP and domain feeds and import it into a running local instance:

```sh
node scripts/import-default-indicators.mjs --import
```

This requires Node.js 22+ on the host. It saves `data/default-indicators.json` for manual import and a separate `data/default-indicators.sources.json` with feed provenance. Run without `--import` to download only. If indicators are already installed, the script refuses to overwrite them unless you explicitly add `--replace`. For a token-protected instance, supply the existing token through the `API_TOKEN` environment variable. Optional `PCAP_LENS_URL` selects another local port.

Source: [Threatview community feeds](https://threatview.io/). These are reputation leads, not verified compromise verdicts. `updated` uses the feed file's HTTP Last-Modified timestamp when available, otherwise retrieval time; neither establishes when an individual indicator was last observed. The script never contacts listed malicious destinations. No automatic refresh is scheduled; rerun when you want a fresh snapshot. Existing reports require reanalysis to use new indicators.

Reputation checks are **unavailable by default**. Import your own trusted JSON feed using **Import indicators**. Each import replaces the existing indicator set; reports retain their analysis-time intelligence status. Importing a feed does not modify old reports. Upload a capture again to assess it against new indicators.

Schema (documentation example only; `example.test` is a reserved test domain, not a malicious-domain claim):

```json
{
  "indicators": [
    {
      "type": "domain",
      "value": "example.test",
      "source": "My curated feed",
      "updated": "2026-11-02T00:00:00Z"
    }
  ]
}
```

Types: `ip` (exact IPv4/IPv6 address) or `domain` (domain and its subdomains). Maximum 100,000 entries / 20 MB per import. Indicators older than 30 days produce lower-confidence findings. Feed source and update timestamps are supplied by the importer, not independently verified. Feed freshness is relative to analysis time, not capture time. IP matches indicate packet observations, not successful connections; domain matches indicate visible names, not proven contact with a malicious server. No automated feed updater is included.

## Resource limits

Defaults in `compose.yaml`:

| Resource | Limit |
| --- | --- |
| Capture upload | 250 MiB |
| Retained capture sizes | 2 GiB (reports and indicators consume additional storage) |
| Packet processing | First 500,000 packets; report shows a partial-analysis notice at the limit |
| Analysis time | 180 seconds per job; jobs exceeding this fail explicitly |
| Unique IP endpoints / flows / names | 5,000 / 50,000 / 20,000; exceeding these fails explicitly |
| Finding groups | First 2,000 groups; evidence examples capped at 10 packet references per group |
| Execution | One analysis at a time; up to 8 queued/running sessions, one concurrent upload |
| Container | 1 GiB memory, 2 CPUs, no added capabilities, non-root, read-only application filesystem |

The UI shows up to 300 filtered rows per view; JSON exports contain all retained report rows. No network interfaces, host networking, or privileged mode are needed. Files are processed by TShark in a child process with a timeout. Keep Docker images updated because packet parsers process untrusted input. This is a personal/home-lab prototype, not a hardened multi-tenant service.

## Access from another machine

Compose binds to **127.0.0.1** by default. For LAN access, copy `.env.example` to `.env`, set a strong random `API_TOKEN`, set `REQUIRE_AUTH=true`, and change the published address to the intended LAN interface, for example `192.168.1.10:8080:8080`. Use HTTPS through your reverse proxy for remote access. Open the app and enter that existing token using **Configure access token**. The browser stores it in tab-scoped session storage and sends it as a Bearer header. This is a single-user shared token, not multi-user accounts. Static UI assets and `/health` are public; all report, capture, indicator, and job endpoints require the configured token. Do not expose the port publicly without appropriate authentication, TLS, and network access controls. The app does not infer safety from Docker's NAT source address.

## Development and verification

Requires Node.js 22+ and TShark on PATH (or `TSHARK_PATH` pointing to its executable). There are no npm dependencies.

```sh
npm start
npm test
```

Outside Docker the server binds to localhost and uses `./data`. Optional variables: `PORT`, `HOST`, `DATA_DIR`, `API_TOKEN`, `REQUIRE_AUTH`, `MAX_UPLOAD_MB`, `MAX_STORAGE_MB`, `ANALYSIS_TIMEOUT_SECONDS`, `TSHARK_PATH`.

Generate a synthetic, non-sensitive PCAP for a manual upload:

```sh
node scripts/make-fixture.mjs sample.pcap
```

It contains 31 packets: a DNS query, a port-scan pattern, and periodic connection attempts. It contains no real network traffic and no real malicious indicator. Without TShark, the real-parser test is explicitly skipped; HTTP tests still verify upload validation, failure handling, authentication, persistence, capture download, and deletion.

For complete tests including real packet parsing using the container's TShark:

```sh
docker build --target test -t pcap-lens-test .
docker run --rm --network none --tmpfs /tmp:rw,size=256m pcap-lens-test
```

`--network none` leaves loopback available for the HTTP tests and prevents outbound network access. The test stage's temporary data lives under `/tmp`; the production image is built with `--target runtime` (already selected by Compose).

## Implementation

Native Node HTTP server streams raw upload bodies to disk (not multipart), runs a bounded single-worker queue, and stores JSON reports in a named volume. TShark reads capture files with name resolution disabled (`-n`) and emits selected fields. The application never runs a shell command using capture contents or supplied filenames. Restarted running/queued analyses are requeued; interrupted uploads are marked failed for deletion.

References: [TShark manual](https://www.wireshark.org/docs/man-pages/tshark), [pfSense capture GUI](https://docs.netgate.com/pfsense/en/latest/diagnostics/packetcapture/webgui.html).
