#!/bin/bash

# ==============================================================================
# ASIR VPS Defense - Automated Deployment Script
# ==============================================================================
# Description:
#   Orchestrates the deployment of a secure VPS infrastructure including:
#   - Docker & Docker Compose installation
#   - Firewall (UFW/NFTables) hardening
#   - Secure SSH configuration (Split Auth)
#   - WAF (Nginx + ModSecurity) setup
#   - Observability Stack (Loki + Promtail + Grafana)
#
# Usage:
#   chmod +x deploy.sh
#   sudo ./deploy.sh
# ==============================================================================

# Exit on error
set -e

echo "[*] Initializing ASIR VPS Defense Deployment..."
