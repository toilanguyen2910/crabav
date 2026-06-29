# Contributing to CrabAV

First off, thank you for considering contributing to CrabAV! It's people like you that make CrabAV such a great tool.

## Where do I go from here?

If you've noticed a bug or have a feature request, make sure to check if there's already an issue for it. If not, open a new issue!

## Setting up the development environment

1. Fork the repo and clone it locally.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up the UI dependencies (if applicable):
   ```bash
   cd ui
   npm install
   ```

## Running Tests

We use `pytest` for running tests. Before submitting a Pull Request, please ensure all tests pass:

```bash
pytest tests/
```

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2. Update the README.md with details of changes to the interface, this includes new environment variables, exposed ports, useful file locations and container parameters.
3. You may merge the Pull Request in once you have the sign-off of two other developers, or if you do not have permission to do that, you may request the second reviewer to merge it for you.

## Code Style

- Please adhere to PEP 8 standards for Python code.
- Write docstrings for all modules, classes, and functions.
- Ensure proper error handling and logging.

Thank you for contributing!
