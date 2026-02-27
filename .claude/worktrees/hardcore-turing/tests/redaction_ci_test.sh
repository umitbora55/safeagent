#!/bin/bash
set -e
echo "🔍 Redaction CI Test"
SECRETS=("sk-ant-api03-FAKE" "pa-FAKETOKEN" "GOCSPX-FAKE" "+1-555-012-3456" "fake@example.com" "123-45-6789")
EXPORT_FILE="$HOME/.local/share/safeagent/export_anonymized.jsonl"
if [ -f "$EXPORT_FILE" ]; then
    FOUND=0
    for secret in "${SECRETS[@]}"; do
        if grep -q "$secret" "$EXPORT_FILE"; then
            echo "❌ FAIL: Secret leaked: $secret"
            FOUND=1
        fi
    done
    [ $FOUND -eq 0 ] && echo "✅ No secrets found in export" || exit 1
else
    echo "⚠️  No export file found (OK for first run)"
fi
echo "✅ Redaction CI test passed"
