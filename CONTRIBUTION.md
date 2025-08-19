### Contributing to MCP Security Analyzer

Thank you for your interest in improving this project. This repository provides static and ML-assisted security analysis for MCP servers and tools, plus runtime hooks for protection. Contributions are welcome across analyzers, runtime hooks, ML integrations, tests, and documentation.

By contributing, you help make the MCP ecosystem safer. Please read this document before opening an issue or pull request.

---

## Quick Start (Development)

- **Requirements**: Python 3.13+, Git, macOS/Linux/WSL
- **Clone**:
  ```bash
  git clone https://github.com/<your-org>/secure-toolings.git
  cd secure-toolings
  ```
- **Install (STRONGLY recommended via uv)**:
  ```bash
  # Install UV package manager
  # macOS (Homebrew):
  brew install uv
  # Or via pip:
  pip install uv
  
  # Install project dependencies
  uv sync
  
  # ALWAYS activate the virtual environment before running commands
  source .venv/bin/activate  # macOS/Linux
  # or
  .venv\Scripts\activate     # Windows
  
  # Verify installation
  python3 mighty_mcp.py --help
  ```
- **Alternative pip install** (not recommended):
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -U pip
  pip install -e .
  ```
- **Optional ML features** (enables advanced analysis):
  ```bash
  # After activating venv
  pip install transformers torch sentence-transformers scikit-learn networkx gitpython
  ```
- **Enable LLM features** (optional):
  ```bash
  echo "CEREBRAS_API_KEY=your_api_key" > .env
  ```

## Repo Map (what to change where)

- `analyzers/comprehensive_mcp_analyzer.py`: Main static analyzer and report generator
- `hooks/mcp_security_hooks.py`: Runtime pre/post/content hooks for MCP tooling
- `src/semantics/`: Semantic analysis and model ensemble. Optional at runtime; the analyzer will use these if ML deps are installed. The CLI report shows an “ML Score” when active.
- `tests/`: End-to-end demo scripts and evaluation suites
- `docs/`: Architecture, usage, and gap analysis docs

Before adding new modules or helpers, search the codebase to avoid duplication and keep things DRY.

## Running The Analyzer & Tests

**IMPORTANT: Always activate the virtual environment first:**
```bash
source .venv/bin/activate  # macOS/Linux
# or
.venv\Scripts\activate     # Windows
```

### Main Entry Points

- **Use the unified CLI** (recommended):
  ```bash
  python3 mighty_mcp.py check .
  python3 mighty_mcp.py check https://github.com/modelcontextprotocol/servers
  ```

- **Direct analyzer** (alternative):
  ```bash
  python3 src/analyzers/comprehensive_mcp_analyzer.py .
  python3 src/analyzers/comprehensive_mcp_analyzer.py https://github.com/modelcontextprotocol/servers
  ```

### Running Tests

**IMPORTANT: Run all tests before submitting a PR:**
```bash
# Run the full test suite (recommended)
cd tests/
./run_all_tests.sh

# Or from project root:
bash tests/run_all_tests.sh
```

Individual test commands:
- Create local test cases (safe/malicious examples):
  ```bash
  python3 tests/create_test_cases.py
  ```
- Run the comprehensive evaluation suite:
  ```bash
  python3 tests/comprehensive_test_suite.py
  ```
- Demo ML-powered analysis (optional ML deps required):
  ```bash
  python3 tests/demo_ml_integration.py
  ```
- Test real MCP servers (network access, may be slow):
  ```bash
  # Test built-in list
  python3 tests/test_real_mcp_servers.py --test-all
  # Or a specific URL
  python3 tests/test_real_mcp_servers.py --url https://github.com/modelcontextprotocol/servers
  ```

### Web Dashboard

- Start the dashboard:
  ```bash
  python3 src/dashboard/app.py
  ```
- Access at: http://localhost:8080
- The database auto-initializes on first use (creates `analysis_cache.db`)

### About semantic analysis usage

- The primary CLI (`analyzers/comprehensive_mcp_analyzer.py`) attempts to initialize the ensemble via `src/semantics/model_ensemble.ModelEnsemble`. If imports fail, it falls back to a local heuristic and continues gracefully. This means:
  - Without ML deps: static + heuristic analysis (no crash).
  - With ML deps: ML/semantic scoring is included in the final report (see “ML Score”).
  - To develop semantic features, install the optional dependencies listed in Quick Start.

Reports from full scans are written to `reports/` with a timestamped filename.

## What Makes a High-Quality Contribution

- **Detection quality**: Reduce false negatives for clearly malicious patterns without inflating false positives on safe code.
- **Precision first**: Prefer high-confidence detections; annotate lower-confidence findings accordingly.
- **DRY and readable**: Reuse existing helpers/patterns; keep changes small and cohesive.
- **Measured impact**: When you add or change patterns, update or add tests under `tests/` that demonstrate improvements.
- **Docs updated**: If you close or narrow a detection gap, reflect it in `DETECTION_GAP_ANALYSIS.md` and, if relevant, `docs/`.

## Areas Where Help Is Most Useful

- Strengthening patterns for: command injection, SSRF, credential theft, path traversal, RADE/tool poisoning
- Expanding AST/data-flow heuristics while keeping runtime fast
- Improving ML integration reliability and model confidence calibration
- Runtime hooks hardening (`hooks/mcp_security_hooks.py`): SSRF, prompt-injection, and leakage filters
- Test coverage: add realistic malicious and safe counterexamples

## Coding Standards (Python)

- Use type hints on public functions and new modules.
- Favor guard clauses over deep nesting; handle error cases early.
- Avoid unsafe constructs (`eval`, `exec`, `shell=True`) outside controlled tests.
- Prefer clear, descriptive names over abbreviations.
- Keep functions focused; avoid multi-purpose utilities.
- Match existing formatting; don’t reformat unrelated code.

## Commit Messages & PRs

- Use concise, informative commits. Conventional Commit prefixes are appreciated: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`, `chore:`.
- Small, focused PRs are easier to review.
- Describe motivation, approach, and trade-offs in the PR description.
- Link any related issues and include before/after behavior when relevant.

### PR Checklist

- [ ] Changes are scoped and readable
- [ ] Analyzer runs locally: `python3 mighty_mcp.py check .`
- [ ] All tests pass: `bash tests/run_all_tests.sh`
- [ ] Relevant tests updated or added under `tests/`
- [ ] No obvious false-positive regressions in safe examples
- [ ] Docs updated if behavior or capabilities changed

## Filing Issues

- Use clear titles and include minimal repros (code snippets or a public repo link if possible).
- Label requests as `bug`, `feature`, or `docs` when you can.
- For detection issues, share the input and what you expected to happen vs. what happened.

## Security & Responsible Disclosure

Because this project focuses on security, please avoid posting exploit details in public issues. If you believe you’ve found a vulnerability in this repository or its published artifacts:

- Report with minimal detail in an issue and request a secure contact method; or
- Use your platform’s private security advisory flow if available (e.g., GitHub Security Advisories).

We will coordinate on remediation before public disclosure.

## Code of Conduct

We are committed to a welcoming and inclusive community. By participating, you agree to be respectful and constructive. We follow the spirit of the Contributor Covenant; a formal `CODE_OF_CONDUCT.md` may be added.

## License

By contributing, you agree that your contributions will be licensed under the repository’s MIT License.

---

Thank you for helping protect the MCP ecosystem. Your contributions—no matter how small—make a real difference.


