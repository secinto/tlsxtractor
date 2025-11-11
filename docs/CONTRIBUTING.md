# Contributing to TLSXtractor

Thank you for your interest in contributing to TLSXtractor! This document provides guidelines and instructions for contributing.

## Code of Conduct

We expect all contributors to be respectful and professional. Please be considerate of others and their perspectives.

## Getting Started

### Development Setup

1. Fork and clone the repository:
```bash
git clone https://github.com/secinto/tlsxtractor.git
cd tlsxtractor
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

4. Install pre-commit hooks:
```bash
pre-commit install
```

### Running Tests

Run the full test suite:
```bash
pytest
```

Run tests with coverage:
```bash
pytest --cov --cov-report=html
```

Run specific test file:
```bash
pytest tests/unit/test_scanner.py
```

Run only unit tests (skip slow integration tests):
```bash
pytest -m "not slow"
```

### Code Quality

We use several tools to maintain code quality:

**Format code:**
```bash
black src/ tests/
isort src/ tests/
```

**Lint code:**
```bash
ruff check src/ tests/
flake8 src/ tests/
```

**Type checking:**
```bash
mypy src/tlsxtractor
```

**Security scan:**
```bash
bandit -r src/
```

**Run all checks:**
```bash
pre-commit run --all-files
```

## Development Workflow

### 1. Create a Branch

Create a descriptive branch name:
```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make Changes

- Write clear, concise commit messages
- Follow the existing code style
- Add tests for new features
- Update documentation as needed

### 3. Test Your Changes

Ensure all tests pass and code quality checks succeed:
```bash
pytest
pre-commit run --all-files
```

### 4. Submit a Pull Request

1. Push your branch to your fork
2. Create a pull request against the `main` branch
3. Describe your changes in detail
4. Link any related issues

## Code Style Guidelines

### Python Style

- Follow PEP 8 guidelines
- Use type hints for all function parameters and return values
- Maximum line length: 100 characters
- Use Black for formatting
- Use isort for import sorting

### Naming Conventions

- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_leading_underscore`

### Docstrings

Use Google-style docstrings:

```python
def example_function(param1: str, param2: int) -> bool:
    """
    Brief description of the function.

    Detailed description if needed. Explain the purpose,
    behavior, and any important notes.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When param2 is negative

    Example:
        >>> example_function("test", 42)
        True
    """
    ...
```

### Testing Guidelines

- Write tests for all new features
- Aim for 85%+ code coverage
- Use descriptive test names: `test_<what>_<when>_<expected>`
- Use fixtures for common setup
- Mock external dependencies

Example test structure:
```python
def test_scan_target_success_returns_domains():
    """Test that successful scan returns discovered domains."""
    # Arrange
    scanner = TLSScanner(timeout=10)

    # Act
    result = await scanner.scan_target("1.1.1.1", 443)

    # Assert
    assert result.status == "success"
    assert len(result.domains) > 0
```

## Project Structure

```
tlsxtractor/
├── src/tlsxtractor/       # Source code
│   ├── __init__.py
│   ├── cli.py             # Command-line interface
│   ├── scanner.py         # TLS scanning logic
│   ├── certificate.py     # Certificate parsing
│   ├── dns_resolver.py    # DNS resolution
│   └── ...
├── tests/                 # Test files
│   ├── unit/              # Unit tests
│   └── integration/       # Integration tests
├── docs/                  # Documentation
├── examples/              # Example files
└── pyproject.toml         # Project configuration
```

## Adding New Features

### 1. Design

- Open an issue to discuss the feature
- Get feedback before implementing
- Consider backwards compatibility

### 2. Implementation

- Keep changes focused and atomic
- Add comprehensive tests
- Update documentation
- Add docstrings

### 3. Performance

- Consider performance implications
- Profile code if needed
- Add benchmarks for critical paths

## Bug Reports

When reporting bugs, please include:

- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## Feature Requests

Feature requests are welcome! Please:

- Search existing issues first
- Describe the problem you're solving
- Explain your proposed solution
- Consider potential drawbacks

## Documentation

- Update README.md for user-facing changes
- Update docstrings for API changes
- Add examples for new features
- Keep documentation concise and clear

## Release Process

(For maintainers)

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create release branch: `release/vX.Y.Z`
4. Run full test suite
5. Tag release: `git tag vX.Y.Z`
6. Push tags: `git push --tags`
7. GitHub Actions will build and publish

## Getting Help

- Open an issue for questions
- Check existing documentation
- Review closed issues for similar problems

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT).

## Recognition

Contributors will be recognized in the project README. Thank you for your contributions!
