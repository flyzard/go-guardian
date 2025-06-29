# File: test.sh
#!/bin/bash

echo "=== Go-Guardian Test Suite ==="
echo

echo "1. Building all packages..."
if ! go build ./...; then
    echo "❌ Build failed. Please fix compilation errors first."
    exit 1
fi
echo "✅ Build successful"
echo

echo "2. Running all tests with race detection..."
if go test -race -coverprofile=coverage.out ./... > test.log 2>&1; then
    echo "✅ All tests passed"
else
    echo "⚠️  Some tests failed (see details below)"
fi
echo

echo "3. Generating coverage report..."
go tool cover -html=coverage.out -o coverage.html 2>/dev/null && echo "✅ Coverage report generated: coverage.html" || echo "⚠️  Coverage report generation skipped"
echo

echo "4. Test Results Summary:"
echo "------------------------"
go test ./... 2>&1 | grep -E "(ok|FAIL)" | while read line; do
    if echo "$line" | grep -q "FAIL"; then
        echo "❌ $line"
    elif echo "$line" | grep -q "ok"; then
        echo "✅ $line"
    fi
done
echo

echo "5. Security Test Results:"
echo "------------------------"
go test -v -run "TestSQL|TestCSRF|TestXSS|TestPassword|TestToken|TestSecurity|TestSession" ./... 2>&1 | grep -E "(PASS|FAIL|---)" | while read line; do
    if echo "$line" | grep -q "FAIL"; then
        echo "❌ $line"
    elif echo "$line" | grep -q "PASS"; then
        echo "✅ $line"
    fi
done
echo

echo "6. Coverage Summary:"
echo "-------------------"
total_coverage=$(go tool cover -func=coverage.out 2>/dev/null | grep total | awk '{print $3}')
echo "Total coverage: ${total_coverage:-N/A}"
echo

echo "Test run complete!"