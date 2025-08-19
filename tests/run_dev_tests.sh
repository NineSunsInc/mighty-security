#!/bin/bash

# MCP Security Suite - Development Test Runner
# Fast testing with dev_mode (no deep analysis, no LLM)

echo "╔══════════════════════════════════════════════════════════╗"
echo "║      MCP Security Suite - Development Test Runner       ║"
echo "║                    (Fast Mode)                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Always run from the directory containing this script (tests/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check if virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo "⚠️  Virtual environment not activated. Activating..."
    if [ -f "../.venv/bin/activate" ]; then
        source ../.venv/bin/activate
    elif [ -f ".venv/bin/activate" ]; then
        source .venv/bin/activate
    else
        echo "❌ Error: Virtual environment not found!"
        echo "Please run 'uv sync' or 'python3 -m venv .venv' first"
        exit 1
    fi
fi

echo "📁 Running development tests from: $(pwd)"
echo "🐍 Python version: $(python3 --version)"
echo "⚡ Mode: Development (fast, no deep analysis)"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                 RUNNING CORE TESTS ONLY                   "
echo "═══════════════════════════════════════════════════════════"
echo ""

# Initialize counters
passed=0
failed=0
skipped=0
failed_tests=""
start_time=$(date +%s)

# Core security tests that must pass
core_tests=(
    "test_categorization_fix.py"
    "test_fingerprint_integrity.py"
    "test_parallel_processing.py"
    "test_security_not_compromised.py"
    "test_unified_pattern_registry.py"
    "test_ast_cache.py"
    "comprehensive_test_suite.py"
)

echo "🔧 Running ${#core_tests[@]} core security tests..."
echo ""

for test in "${core_tests[@]}"; do
    if [ ! -f "$test" ]; then
        echo "⚠️  Test file not found: $test"
        continue
    fi
    
    # Display test name with formatting
    printf "%-50s" "$test:"
    
    # Run the test and capture result
    if python3 "$test" > /dev/null 2>&1; then
        echo "✅ PASS"
        ((passed++))
    else
        echo "❌ FAIL"
        ((failed++))
        failed_tests="$failed_tests\n  - $test"
    fi
done

# Calculate execution time
end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                   DEVELOPMENT TEST SUMMARY                 "
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "📊 Results:"
echo "  ✅ Passed:  $passed"
echo "  ❌ Failed:  $failed"

# Calculate success rate
total=$((passed + failed))
if [ $total -gt 0 ]; then
    success_rate=$(( passed * 100 / total ))
    echo ""
    echo "📈 Success Rate: $success_rate%"
fi

echo "⏱️  Duration: ${duration}s (dev mode)"

# Show failed tests if any
if [ $failed -gt 0 ]; then
    echo ""
    echo "❌ Failed Tests:"
    echo -e "$failed_tests"
    echo ""
    echo "💡 Tip: Run individual failed tests for detailed output:"
    echo "   python3 tests/<test_name>.py"
fi

# Final status
echo ""
if [ $failed -eq 0 ]; then
    echo "✨ SUCCESS: All core security tests passed! ✨"
    echo "🚀 Ready for development work"
    exit 0
else
    echo "⚠️  WARNING: $failed core test(s) failed"
    echo "🚨 Security may be compromised - fix before continuing"
    exit 1
fi