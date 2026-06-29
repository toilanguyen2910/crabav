#!/usr/bin/env python
"""
CrabAV Installation Script
"""

import os
import sys
import subprocess
from pathlib import Path


def check_python_version():
    """Check Python version"""
    if sys.version_info < (3, 11):
        print("❌ Python 3.11+ required")
        print(f"Current: Python {sys.version_info.major}.{sys.version_info.minor}")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True


def install_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False


def check_clamav():
    """Check if ClamAV is installed"""
    print("\n🦠 Checking ClamAV...")
    
    try:
        result = subprocess.run(
            ["clamscan", "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("✅ ClamAV installed")
            return True
    except FileNotFoundError:
        pass
    
    print("⚠️  ClamAV not found (optional)")
    print("   Download: https://www.clamav.net/downloads")
    return False


def create_directories():
    """Create required directories"""
    print("\n📁 Creating directories...")
    
    dirs = [
        "data/quarantine",
        "data/backups",
        "logs",
        "data/database"
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    print("✅ Directories created")
    return True


def setup_config():
    """Setup configuration"""
    print("\n⚙️  Configuration...")
    
    if not Path("config.yaml").exists():
        print("❌ config.yaml not found")
        return False
    
    print("✅ Configuration ready")
    return True


def main():
    """Main installation"""
    print("=" * 60)
    print("🦀 CrabAV Installation")
    print("=" * 60)
    
    # Check Python
    if not check_python_version():
        return 1
    
    # Install dependencies
    if not install_dependencies():
        return 1
    
    # Create directories
    if not create_directories():
        return 1
    
    # Check ClamAV
    check_clamav()
    
    # Setup config
    if not setup_config():
        return 1
    
    print("\n" + "=" * 60)
    print("✅ Installation complete!")
    print("=" * 60)
    print("\nQuick start:")
    print("  python -m src                  # Interactive mode")
    print("  python -m src /path/to/scan    # Scan directory")
    print("\nWith UI:")
    print("  cd ui")
    print("  npm install")
    print("  npm run electron-dev")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
