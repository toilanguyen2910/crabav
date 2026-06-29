# CrabAV - Free Multi-Agent Antivirus 🦀

**Version:** 0.1.0  
**Status:** Beta - Core functionality complete

CrabAV is a free, open-source antivirus system powered by specialized AI agents. Unlike traditional antivirus software, CrabAV **never takes action automatically** - it always asks for your approval first.

## 🎯 Key Features

- **Multi-Agent Architecture**: Specialized agents for different detection methods
- **User Approval Required**: Never auto-deletes - always asks first
- **Transparent Detection**: See exactly what each agent found and why
- **Multiple Detection Layers**: Signature-based, heuristic, behavioral analysis
- **Real-time Monitoring**: Watchdog-based file system monitoring
- **Safe Quarantine**: Isolated storage with backup and restore
- **Beautiful Dark UI**: Electron + React desktop application
- **Privacy-First**: All scanning happens locally on your machine

## 🏗️ Architecture

```
┌─ Desktop UI (Electron + React) ─┐
│  Dashboard | Threats | Scans    │
└───────────────┬──────────────────┘
                │ IPC Bridge
┌───────────────▼──────────────────┐
│     ORCHESTRATOR                 │
│  • Coordinates agents            │
│  • Parallel execution            │
│  • Result aggregation            │
└────┬─────────────────────────┬───┘
     │                         │
┌────▼────────┐       ┌────────▼────┐
│ Scanner     │       │ Monitor     │
│ Agents      │       │ Agents      │
└────┬────────┘       └────┬────────┘
     │                     │
┌────▼─────────────────────▼─────┐
│  DECISION ENGINE               │
│  • Threat Scoring              │
│  • Action Recommendation       │
└────┬───────────────────────────┘
     │
┌────▼────────────────────────────┐
│  APPROVAL HANDLER (Your Control)│
│  ✅ Quarantine                  │
│  ✅ Delete                       │
│  ✅ Whitelist                    │
└────┬────────────────────────────┘
     │
┌────▼──────────────┐
│ Action Executor   │
│  • Execute action │
│  • Log results    │
└───────────────────┘
```

## 🚀 Quick Start

### Prerequisites

**Backend (Python):**
- Python 3.11 or higher
- pip (Python package manager)

**Frontend (Optional - for UI):**
- Node.js 18+ and npm
- Electron-compatible system

**External Tools:**
- ClamAV (for signature scanning)
  - Windows: Download from https://www.clamav.net/downloads
  - Linux: `sudo apt install clamav`
  - macOS: `brew install clamav`

### Installation

#### 1. Clone Repository

```bash
git clone https://github.com/yourusername/crabav.git
cd crabav
```

#### 2. Setup Python Backend

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### 3. Setup UI (Optional)

```bash
cd ui
npm install
cd ..
```

#### 4. Configure

Edit `config.yaml` to customize settings:

```yaml
agents:
  file_scanner:
    enabled: true
    use_clamav: true
  
  file_monitor:
    enabled: true
    watch_downloads: true
```

### Running CrabAV

#### Backend Only (CLI)

```bash
# Quick scan a directory
python -m src /path/to/scan

# Or run interactively
python -m src
```

#### With UI

```bash
# Terminal 1: Start backend
python -m src

# Terminal 2: Start UI
cd ui
npm run electron-dev
```

## 📖 Usage

### Command Line

```bash
# Scan Downloads folder
python -m src ~/Downloads

# Scan specific file
python -m src /path/to/suspicious.exe
```

### Desktop UI

1. **Dashboard**: View system status and quick actions
2. **Threats**: Review detected threats and approve actions
3. **Scans**: Start scans and view history
4. **Settings**: Configure scanning behavior

### Approval Workflow

When a threat is detected:

1. CrabAV shows threat details:
   - Threat name
   - Risk score (0-100)
   - Which agents detected it
   - Evidence and confidence
   
2. You choose an action:
   - **Quarantine**: Safely isolate (recommended)
   - **Delete**: Permanently remove (backup kept)
   - **Whitelist**: Mark as safe
   - **Ignore**: Do nothing

3. CrabAV executes your choice

## 🛡️ Agent Types

### Scanner Agents

**File Scanner** (ClamAV + YARA)
- Signature matching against known threats
- Hash verification
- Packer detection
- Confidence: 95%+

**Registry Scanner** (Phase 2)
- Startup persistence detection
- Service configuration changes
- Browser modifications

**Memory Scanner** (Phase 2)
- Running process analysis
- DLL injection detection
- Suspicious API calls

### Monitor Agents

**File System Monitor** (watchdog)
- Real-time file creation/modification
- Suspicious pattern detection
- Downloads folder monitoring

**Process Monitor** (Phase 2)
- Process creation tracking
- Parent-child anomalies
- Execution path analysis

### Analysis Agents

**Heuristic Analyzer** (Phase 2)
- Behavioral pattern matching
- Entropy analysis
- Import table inspection

**ML Classifier** (Phase 3)
- Machine learning classification
- Unknown malware detection
- Family identification

## 🔧 Configuration

### Key Settings

```yaml
scanning:
  real_time: true
  max_file_size_mb: 100
  exclude_paths:
    - C:\Windows\WinSxS
    - C:\$Recycle.Bin

agents:
  file_scanner:
    enabled: true
    use_clamav: true
    scan_archives: true

quarantine:
  max_size_mb: 1024
  auto_delete_days: 30
  create_restore_point: true
```

## 📊 Project Status

### ✅ Completed (Phase 1-3)

- [x] Base agent framework
- [x] File scanner agent (ClamAV)
- [x] File system monitor (watchdog)
- [x] Orchestrator & coordination
- [x] State management (SQLite)
- [x] Decision engine & threat scoring
- [x] Approval workflow
- [x] Quarantine manager
- [x] Action executor
- [x] Desktop UI (Electron + React)
- [x] Main application entry point

### 🚧 In Progress / Planned

- [ ] Registry scanner agent
- [ ] Process monitor agent
- [ ] Heuristic analysis agent
- [ ] ML classification agent
- [ ] Unit tests & integration tests
- [ ] IPC handler implementation
- [ ] Performance optimization
- [ ] Installer/packager

## 🧪 Testing

### Test with EICAR

EICAR is a safe test file recognized by all antivirus software:

```bash
# Create EICAR test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt

# Scan it
python -m src eicar.txt
```

CrabAV should detect it and ask for your approval.

## 🤝 Contributing

Contributions welcome! Areas that need help:

- Additional agent implementations
- UI improvements
- Documentation
- Testing
- Translations

## 📝 License

Apache License 2.0 - See [LICENSE](LICENSE)

## 🙏 Credits

- ClamAV for signature database
- YARA for rule engine
- Electron for desktop framework
- React & Material-UI for UI components

## ⚠️ Disclaimer

CrabAV is beta software for educational purposes. While it implements real antivirus techniques, it should not be your only line of defense. Use alongside other security measures.

## 📧 Support

- Issues: [GitHub Issues](https://github.com/yourusername/crabav/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/crabav/discussions)
- Email: support@crabav.local

---

**Made with 🦀 by Súp Cua AI**
