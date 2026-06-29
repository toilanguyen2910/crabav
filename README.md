# CrabAV - Free Multi-Agent Antivirus

🦀 **CrabAV** is a free, open-source antivirus system powered by AI expert agents.

## Key Features

- **Multi-Agent Architecture**: Specialized AI agents for different detection methods
- **User Approval Required**: Never auto-deletes - always asks before taking action
- **Transparent Detection**: See exactly what each agent found and why
- **Multiple Detection Layers**: Signature-based, heuristic, behavioral analysis
- **Privacy-First**: All scanning happens locally on your machine

## Architecture

```
User Interface (Electron + React)
         ↓
    Orchestrator
         ↓
  ┌──────┴──────┐
  ↓      ↓      ↓
Scanner Monitor Analysis
Agents  Agents  Agents
```

## Agent Types

### Scanner Agents
- **File Scanner**: ClamAV + YARA signature matching
- **Registry Scanner**: Detects startup persistence
- **Memory Scanner**: Analyzes running processes

### Monitor Agents
- **File System Monitor**: Real-time file change detection
- **Process Monitor**: Tracks process creation/behavior
- **Network Monitor**: (Phase 2) Network connection analysis

### Analysis Agents
- **Heuristic Agent**: Pattern-based detection
- **ML Agent**: (Phase 2) Machine learning classification
- **Threat Intel**: Cross-reference with known threats

## Tech Stack

- **Python 3.11+**: Core engine
- **ClamAV**: Signature database
- **YARA**: Custom rule engine
- **CrewAI**: Multi-agent orchestration
- **SQLite**: Local data storage
- **Electron + React**: Desktop UI
- **watchdog**: File system monitoring
- **psutil + WMI**: Process monitoring

## Project Status

🚧 **Phase 1 - In Development**

- [x] Research & design
- [x] Technical specification
- [ ] Core infrastructure
- [ ] Base agent framework
- [ ] Scanner agents
- [ ] UI development

## Installation

```bash
# Coming soon
pip install crabav
```

## Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/crabav.git
cd crabav

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run development version
python -m crabav
```

## Documentation

Full technical specification: [docs/technical-spec.md](docs/technical-spec.md)

## License

Apache License 2.0 - See [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## Security

Found a security issue? Please email security@crabav.local

---

Made with 🦀 by Súp Cua AI
