# Additional Agents for CrabAV

## Phase 4 Planned Agents

### 1. Process Monitor Agent
```python
# Monitor running processes for suspicious behavior
- Parent-child process analysis
- API call monitoring
- Memory injection detection
- Network connection tracking
```

### 2. Registry Scanner Agent
```python
# Detect persistence mechanisms
- Startup keys scanning
- Service modifications
- Browser helper object detection
- Shell extension scanning
```

### 3. Heuristic Analyzer Agent
```python
# Behavioral pattern analysis
- Entropy analysis
- Packer detection
- Import table analysis
- Code sections analysis
```

### 4. ML Classifier Agent (Phase 5)
```python
# Machine learning-based classification
- Unknown malware detection
- Family identification
- Confidence scoring
```

## Implementation Status

- [x] File Scanner (ClamAV)
- [x] File Monitor (watchdog)
- [ ] Process Monitor
- [ ] Registry Scanner
- [ ] Heuristic Analyzer
- [ ] ML Classifier
