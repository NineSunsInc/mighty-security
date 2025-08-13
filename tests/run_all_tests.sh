#!/bin/bash

# MCP Security Suite - Full Test Runner
# This script runs all tests in the tests/ directory and provides a summary

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         MCP Security Suite - Full Test Runner           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

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

echo "📁 Running tests from: $(pwd)"
echo "🐍 Python version: $(python3 --version)"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                    RUNNING ALL TESTS                       "
echo "═══════════════════════════════════════════════════════════"
echo ""

# Initialize counters
passed=0
failed=0
skipped=0
failed_tests=""
start_time=$(date +%s)

# Find and run all Python test files
for test in *.py; do
    # Skip non-test files (validation and verification scripts are not unit tests)
    if [[ "$test" == "__"* ]] || [[ "$test" == "validate_"* ]] || [[ "$test" == "verify_"* ]]; then
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
echo "                      TEST SUMMARY                          "
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "📊 Results:"
echo "  ✅ Passed:  $passed"
echo "  ❌ Failed:  $failed"
if [ $skipped -gt 0 ]; then
    echo "  ⏭️  Skipped: $skipped"
fi

# Calculate success rate
total=$((passed + failed))
if [ $total -gt 0 ]; then
    success_rate=$(( passed * 100 / total ))
    echo ""
    echo "📈 Success Rate: $success_rate%"
fi

echo "⏱️  Duration: ${duration}s"

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
    echo "✨ SUCCESS: All tests passed! ✨"
    exit 0
else
    echo "⚠️  WARNING: $failed test(s) failed"
    echo "Please fix failing tests before committing changes"
    exit 1
fi