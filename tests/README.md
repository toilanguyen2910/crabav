# Test suite for CrabAV

Run tests with:
```bash
pytest tests/ -v
```

## Test Structure

- `test_core.py` - Unit tests for individual components
- `test_integration.py` - Integration tests for workflows
- `conftest.py` - Shared fixtures and configuration

## Coverage

- Decision Engine (threat scoring)
- Approval Handler (workflow)
- Quarantine Manager (file isolation)
- Full scan workflow
- Agent initialization
