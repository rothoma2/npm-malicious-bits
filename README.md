# npm-malicious-bits

A command-line tool for collecting and managing Indicators of Compromise (IOCs) from malicious Open Source Software (OSS) packages reports across multiple ecosystems and OSINT reports. Unfortunately Open Source Supply Chain Security is under threat at the moment by Nation State Actors.

## Overview

`npm-malicious-bits` helps security researchers and developers track and analyze malicious packages across various package ecosystems including npm, PyPI, Maven, RubyGems, NuGet, Go, and crates.io. The tool automatically collects IOCs from trusted sources and provides powerful filtering capabilities to identify recently published threats.

## Features

- 🔍 **Multi-source Collection**: Collects IOCs from trusted sources like the OpenSSF Malicious Packages repository, AIKIDO API.
- ⏱️ **Time-based Filtering**: Filter packages by publication date with customizable lookback windows
- 📊 **Ecosystem Analysis**: Track malicious packages across multiple package ecosystems
- 💾 **OSV Format**: Standard OSV Format across supported sources
- 🚀 **Easy to Use**: Simple CLI interface with intuitive commands

## Installation

### Using Poetry (recommended)

```bash
# Clone the repository
git clone https://github.com/rothoma2/npm-malicious-bits.git
cd npm-malicious-bits
python -m venv .venv
source .venv/bin/activate

# Install dependencies
poetry install

## Usage

### Collect IOCs from OpenSSF

Collect malicious package IOCs from the OpenSSF Malicious Packages repository:

```bash
npm-iocs collect
```

This will:
- Clone the OpenSSF malicious packages repository
- Collect from the Aikido Intel API latest reports.
- Count and report the number of JSON files containing IOCs
- Display statistics about the collected data


### Parse Recent Packages

Filter and display packages published within a specific time window (default: 72 hours):

```bash
npm-iocs recent
```

Example with custom time window (last 24 hours):

```bash
npm-iocs recent --hours 24
```

This will display:
- Total number of files processed
- Number of packages found within the time window
- Affected ecosystems
- Detailed IOC information including:
  - Package names
  - Ecosystem
  - Publication dates
  - Malware IDs
  - Summaries


### Clone OpenSSF Repository

Clone the OpenSSF malicious packages repository locally:

```bash
npm-iocs clone-ossf --path /path/to/local/directory
```


## Data Sources

### Currently Supported

- **[OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)**: A comprehensive repository maintained by the Open Source Security Foundation containing reports of malicious packages across multiple ecosystems.

- **[Aikido Open Source Threat Feed](https://www.aikido.dev/blog/launching-aikido-malware---open-source-threat-feed)**: A real-time malware detection API powered by Aikido Security that monitors npm packages and provides instant threat intelligence. The feed analyzes packages using multiple detection methods and provides up-to-date information on malicious packages with low false positive rates.

### Planned Support

- GitHub Security Advisories
- OSV Database
- Custom feeds


## Examples

### Daily Threat Monitoring

Check for new threats published in the last 24 hours:

```bash
npm-iocs recent --hours 24 
```

### Weekly Security Review

Generate a weekly report of all threats from the past 7 days:

```bash
npm-iocs recent --hours 168 /path/to/ossf/repo/osv/malicious \
  --output weekly_threats_$(date +%Y%m%d).json
```

### Ecosystem-specific Analysis

After collecting data, filter the JSON output by ecosystem using standard tools:

```bash
npm-iocs recent --hours 72 /path/to/packages --output recent.json
cat recent.json | jq '.recent_packages[] | select(.ecosystem == "npm")'
```

## Development

### Requirements

- Python >= 3.12
- Poetry
- Git

### Running Tests

```bash
pytest
```

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- [OpenSSF](https://openssf.org/) for maintaining the malicious packages database
- [Aikido Security](https://www.aikido.dev/) for providing the Open Source Threat Feed API


## Support

For issues, questions, or contributions, please visit:
- **GitHub**: https://github.com/rothoma2/npm-malicious-bits
- **Issues**: https://github.com/rothoma2/npm-malicious-bits/issues

---

**⚠️ Disclaimer**: This tool is for security research and defensive purposes only. Always verify findings and follow responsible disclosure practices.
