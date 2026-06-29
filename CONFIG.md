# CrabAV Configuration Reference

## Main Config (config.yaml)

### Agents
```yaml
agents:
  file_scanner:
    enabled: true
    use_clamav: true
    scan_archives: true
  
  file_monitor:
    enabled: true
    watch_downloads: true
```

### Scanning
```yaml
scanning:
  real_time: true
  max_file_size_mb: 100
  exclude_paths:
    - C:\Windows\WinSxS
    - C:\$Recycle.Bin
```

### Quarantine
```yaml
quarantine:
  storage_path: ./data/quarantine
  backup_path: ./data/backups
  max_size_mb: 1024
  auto_delete_days: 30
```

### Approval
```yaml
approval:
  timeout_minutes: 30
  require_confirmation: true
```

## Custom Rules

Create custom threat detection rules in `rules/custom.yara`:

```yara
rule Suspicious_Behavior {
    strings:
        $cmd = "cmd.exe /c" nocase
        $powershell = "powershell" nocase
    condition:
        any of them
}
```

## Exclusions

Add exclusions to prevent scanning:

```bash
# Path exclusions
crabav exclude add-path "C:\Program Files\MyApp\*"

# File type exclusions
crabav exclude add-ext ".tmp"

# Process exclusions
crabav exclude add-process "myapp.exe"
```
