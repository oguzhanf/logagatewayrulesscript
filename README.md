# OMS Gateway Domain Monitor

A PowerShell script that automatically monitors OMS Gateway logs for forbidden domain events and adds allowed domains to the gateway configuration.

## What it does

The script monitors the OMS Gateway event logs for Event ID 105 (forbidden domain events). When it finds a domain that was blocked but is on the allowed domains list, it automatically:

1. Adds the domain to the OMS Gateway allowed hosts configuration
2. Restarts the OMS Gateway service to apply the changes
3. Logs all activities for audit purposes

## Key Features

- Monitors events within a configurable time window (default: 1 hour)
- Uses a predefined list of Microsoft Azure and security-related domains
- Supports external configuration file for custom allowed domains
- Comprehensive logging with timestamps and severity levels
- Validates hostname formats before processing
- Prevents duplicate entries in the allowed hosts list

## Usage

```powershell
# Run with default settings (1 hour lookback)
.\scheduledScriptToCheckForbiddenDomainsAgainstAllowedURLs.ps1

# Check events from the last 24 hours
.\scheduledScriptToCheckForbiddenDomainsAgainstAllowedURLs.ps1 -TimeWindowHours 24

# Use custom allowed domains file
.\scheduledScriptToCheckForbiddenDomainsAgainstAllowedURLs.ps1 -AllowedDomainsPath "C:\Config\allowed_domains.txt"
```

## Requirements

- Administrative privileges (required to modify OMS Gateway configuration)
- OMS Gateway service installed and configured
- PowerShell execution policy allowing script execution

## Intended Use

This script is designed to run as a scheduled task to automatically resolve connectivity issues when legitimate Microsoft services are blocked by the OMS Gateway.
