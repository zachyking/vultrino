#!/bin/bash
# Multi-Agent Setup with Scoped API Keys
# This script demonstrates setting up multiple AI agents with different access levels

set -e

echo "=== Multi-Agent Setup with Vultrino ==="
echo

# Prerequisites: vultrino init already done, web server running

# Step 1: Create scoped roles
echo "Step 1: Create scoped roles for different purposes"
echo

echo "# GitHub-only access for code agents"
echo "$ vultrino role create github-agent \\"
echo "    --permissions read,execute \\"
echo "    --scopes 'github-*'"
echo

echo "# Payment processing (Stripe, PayPal)"
echo "$ vultrino role create payment-agent \\"
echo "    --permissions execute \\"
echo "    --scopes 'stripe-*,paypal-*'"
echo

echo "# Read-only for monitoring"
echo "$ vultrino role create monitor \\"
echo "    --permissions read \\"
echo "    --scopes '*'"
echo

echo "# Development only (no production)"
echo "$ vultrino role create dev-agent \\"
echo "    --permissions read,execute \\"
echo "    --scopes '*-dev,*-staging,*-test'"
echo

# Step 2: Create API keys for each agent
echo "Step 2: Create API keys for each agent"
echo

echo "# Claude Code agent (GitHub access)"
echo "$ vultrino key create claude-code --role github-agent"
echo "# → vk_claude_xxx"
echo

echo "# Payment service"
echo "$ vultrino key create payment-service --role payment-agent"
echo "# → vk_payment_xxx"
echo

echo "# Monitoring dashboard"
echo "$ vultrino key create grafana --role monitor"
echo "# → vk_grafana_xxx"
echo

echo "# Development AI agent"
echo "$ vultrino key create dev-claude --role dev-agent"
echo "# → vk_devclaude_xxx"
echo

# Step 3: Example usage by each agent
echo "Step 3: Each agent uses their scoped key"
echo

echo "# Claude Code can access github-* credentials"
echo "$ vultrino --key vk_claude_xxx request github-api https://api.github.com/user"
echo "# ✓ Works"
echo

echo "# Claude Code cannot access payment credentials"
echo "$ vultrino --key vk_claude_xxx request stripe-prod https://api.stripe.com/v1/customers"
echo "# ✗ Error: Access denied to credential: stripe-prod"
echo

echo "# Payment service can only execute (not list)"
echo "$ vultrino --key vk_payment_xxx request stripe-prod https://api.stripe.com/v1/customers"
echo "# ✓ Works"
echo

echo "# Monitor can list but not execute"
echo "$ curl -H 'Authorization: Bearer vk_grafana_xxx' http://localhost:7879/api/v1/credentials"
echo "# ✓ Returns list of all credentials"
echo

# Step 4: List all keys
echo "Step 4: View all API keys"
echo "$ vultrino key list"
echo "# Prefix      Name            Role           Expires    Last Used"
echo "# vk_clau...  claude-code     github-agent   never      2024-01-15"
echo "# vk_paym...  payment-service payment-agent  never      2024-01-15"
echo "# vk_graf...  grafana         monitor        never      2024-01-15"
echo "# vk_devc...  dev-claude      dev-agent      never      2024-01-15"
echo

echo "=== Done! ==="
echo
echo "Each agent now has:"
echo "  - Isolated access to only their required credentials"
echo "  - No visibility into other services' secrets"
echo "  - Audit trail via key identification"
