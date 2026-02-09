# Asphalt Analyze CLI

CLI for analyzing `.pcap` / `.pcapng` files and producing a JSON report with traffic statistics, flow analysis, and anomaly signals.

**What it does**
- Reads packet captures (PCAP or PCAPNG).
- Decodes packets into a normalized schema.
- Runs a configurable set of analyzers.
- Emits a single JSON report to stdout or a file.

**Features**
- Auto-detects PCAP vs PCAPNG by extension or magic bytes.
- Analyzer registry with a sensible default set.
- Optional packet filtering with a small expression language.
- Time-series rollups and flow-level summaries.

**Requirements**
- Python 3.9+ recommended
- `click` (see `requirements.txt`)

**Install**
```bash
python -m pip install -r requirements.txt
```

**Quick start**
```bash
python run.py capture.pcapng --output report.json
```

**Usage**
```bash
python run.py <capture.pcap|capture.pcapng> [options]
```

**Options**
- `--limit`: Max packets to analyze (0 = no limit)
- `--analyzers`: Comma-separated analyzer list
- `--bucket-ms`: Time-series bucket size in milliseconds
- `--chunk-size`: Packet chunk size for `packet_chunks`
- `--scan-port-threshold`: Unique dst port threshold for scan detection
- `--rst-ratio-threshold`: TCP RST ratio threshold for abnormal detection
- `--format`: Output format (currently `json` only)
- `--output`: Write JSON to file instead of stdout
- `--filter`: Filter expression for decoded packets

**Default analyzers**
- `capture_health`
- `global_stats`
- `protocol_mix`
- `flow_summary`
- `flow_analytics`
- `tcp_handshakes`
- `tcp_reliability`
- `tcp_performance`
- `abnormal_activity`
- `scan_signals`
- `arp_lan_signals`
- `dns_anomalies`
- `packet_chunks`
- `time_series`
- `throughput_peaks`
- `packet_size_stats`
- `l2_l3_breakdown`
- `top_entities`

**Filtering**
The `--filter` option accepts a small expression language.

Operators:
- Comparison: `=`, `!=`, `>`, `>=`, `<`, `<=`
- Contains: `~`
- Boolean: `and`, `or`, `not`
- Grouping: parentheses

Examples:
```bash
python run.py capture.pcapng --filter "ip_protocol = 6 and dst_port = 443"
python run.py capture.pcapng --filter "dns_rcode = nxdomain"
python run.py capture.pcapng --filter "app ~ http or app ~ tls"
```

Common fields include:
- `src_ip`, `dst_ip`, `src_port`, `dst_port`
- `ip_protocol`, `l4_protocol`, `tcp_flags_names`
- `dns_qname`, `dns_rcode`
- OSI tags: `osi_tags`, `l2`, `l3`, `l4`, `app`

**Output**
The JSON report includes:
- Capture metadata and basic stats
- Global analyzer results
- Flow-level analyzer results
- Time-series analyzer results
- OSI tag summary

**Project layout**
- `run.py`: CLI entry point
- `src/asphalt_cli/analyze.py`: CLI command and options
- `src/analysis/`: analysis engine, analyzers, models
- `src/pcap_loader/`: PCAP/PCAPNG readers
- `src/capture/`: packet decoding
- `src/utils/`: filters and helpers
