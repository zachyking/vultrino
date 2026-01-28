#!/bin/bash
# Vultrino HTTP API Examples with curl
# These examples show direct API usage for any HTTP client

# Configuration
VULTRINO_URL="${VULTRINO_URL:-http://127.0.0.1:7879}"
API_KEY="${VULTRINO_API_KEY:-vk_your_key_here}"

echo "=== Vultrino HTTP API Examples ==="
echo "Base URL: $VULTRINO_URL"
echo

# Health check (no auth required)
echo "1. Health Check"
echo "curl $VULTRINO_URL/api/v1/health"
echo
curl -s "$VULTRINO_URL/api/v1/health" | jq .
echo
echo

# List credentials
echo "2. List Credentials"
echo "curl -H 'Authorization: Bearer \$API_KEY' $VULTRINO_URL/api/v1/credentials"
echo
curl -s -H "Authorization: Bearer $API_KEY" "$VULTRINO_URL/api/v1/credentials" | jq .
echo
echo

# Execute GET request
echo "3. Execute GET Request"
echo 'curl -X POST $VULTRINO_URL/api/v1/execute \'
echo '     -H "Authorization: Bearer $API_KEY" \'
echo '     -H "Content-Type: application/json" \'
echo '     -d '"'"'{"credential":"github-api","method":"GET","url":"https://api.github.com/user"}'"'"
echo
cat << 'EOF'
# Response format:
{
  "status": 200,
  "headers": {"content-type": "application/json", ...},
  "body": "{\"login\":\"username\",...}"
}
EOF
echo
echo

# Execute POST request with body
echo "4. Execute POST Request with Body"
cat << 'EOF'
curl -X POST $VULTRINO_URL/api/v1/execute \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "credential": "stripe-api",
       "method": "POST",
       "url": "https://api.stripe.com/v1/customers",
       "headers": {"Content-Type": "application/x-www-form-urlencoded"},
       "body": "email=test@example.com"
     }'
EOF
echo
echo

# Execute with query parameters
echo "5. Execute with Query Parameters"
cat << 'EOF'
curl -X POST $VULTRINO_URL/api/v1/execute \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "credential": "github-api",
       "method": "GET",
       "url": "https://api.github.com/search/repositories",
       "query": {"q": "vultrino", "per_page": "5"}
     }'
EOF
echo
echo

# Error handling examples
echo "6. Error Responses"
echo

echo "Missing API key:"
cat << 'EOF'
curl $VULTRINO_URL/api/v1/credentials
# {"error":"Authorization header with Bearer token required","code":"missing_api_key"}
EOF
echo

echo "Invalid API key:"
cat << 'EOF'
curl -H "Authorization: Bearer vk_invalid" $VULTRINO_URL/api/v1/credentials
# {"error":"API key not found","code":"invalid_api_key"}
EOF
echo

echo "Permission denied:"
cat << 'EOF'
# Using a read-only key for execute:
curl -X POST $VULTRINO_URL/api/v1/execute \
     -H "Authorization: Bearer $READONLY_KEY" \
     -H "Content-Type: application/json" \
     -d '{"credential":"github-api","method":"GET","url":"https://api.github.com/user"}'
# {"error":"API key does not have 'execute' permission","code":"permission_denied"}
EOF
echo

echo "Credential scope denied:"
cat << 'EOF'
# Using a github-only key for stripe:
curl -X POST $VULTRINO_URL/api/v1/execute \
     -H "Authorization: Bearer $GITHUB_ONLY_KEY" \
     -H "Content-Type: application/json" \
     -d '{"credential":"stripe-api","method":"GET","url":"https://api.stripe.com/v1/customers"}'
# {"error":"Access denied to credential: stripe-api","code":"credential_denied"}
EOF
echo

echo "=== Done! ==="
