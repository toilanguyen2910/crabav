# Build CrabAV Executable

## Windows

Using PyInstaller:

```bash
pip install pyinstaller
pyinstaller crabav.spec
```

Output: `dist/CrabAV.exe`

## Manual Build

```bash
pyinstaller --onefile --name CrabAV src/__main__.py
```

## Distribution

Create installer:

```bash
# Using NSIS or Inno Setup
# Package dist/CrabAV.exe with config.yaml
```

## Size Optimization

- Use UPX compression
- Exclude unused modules
- Strip debug symbols

Expected size: ~50-80 MB (includes Python runtime)
