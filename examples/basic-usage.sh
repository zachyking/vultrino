#!/bin/bash
# Vultrino Basic Usage Example
# This script demonstrates the core workflow with API keys

set -e

echo "=== Vultrino Basic Usage ==="
echo

# Step 1: Initialize (first-time setup)
echo "Step 1: Initialize Vultrino"
echo "$ vultrino init"
echo "# You'll be prompted for:"
echo "#   - Storage password (encrypts credentials at rest)"
echo "#   - Admin username (for web UI)"
echo "#   - Admin password (for web UI)"
echo

# Step 2: Add credentials
echo "Step 2: Add credentials"
echo "$ vultrino add --alias github-api --key ghp_your_github_token"
echo "$ vultrino add --alias stripe-api --key sk_test_xxx"
echo "$ vultrino add --alias openai --key sk-xxx"
echo

# Step 3: List credentials
echo "Step 3: List credentials"
echo "$ vultrino list"
echo "# Output:"
echo "# ALIAS        TYPE      ID                                    DESCRIPTION"
echo "# github-api   api_key   a1b2c3d4-...                         -"
echo "# stripe-api   api_key   e5f6g7h8-...                         -"
echo "# openai       api_key   i9j0k1l2-...                         -"
echo

# Step 4: Start the web server
echo "Step 4: Start the web server"
echo "$ vultrino web &"
echo "# Server runs at http://127.0.0.1:7879"
echo

# Step 5: Create an API key
echo "Step 5: Create an API key for your application"
echo "$ vultrino key create my-agent --role executor"
echo "# Output:"
echo "# API key created successfully!"
echo "# Key: vk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
echo "#"
echo "# *** SAVE THIS KEY - IT WILL NOT BE SHOWN AGAIN ***"
echo

# Step 6: Use API key for requests
echo "Step 6: Make requests with API key (no password needed!)"
echo "$ vultrino --key vk_a1b2c3... request github-api https://api.github.com/user"
echo

# Step 7: Revoke key when done
echo "Step 7: Revoke API key when no longer needed"
echo "$ vultrino key revoke vk_a1b2c3..."
echo

echo "=== Done! ==="
