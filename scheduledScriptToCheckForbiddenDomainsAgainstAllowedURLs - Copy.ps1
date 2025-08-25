# Script: scheduledScriptToCheckForbiddenDomainsAgainstAllowedURLs.ps1
# Description: Monitors OMS Gateway logs for forbidden domain events and adds allowed domains to the gateway configuration
# Author: Oguzhan Filizlibay
# Last Modified: $(Get-Date -Format "yyyy-MM-dd")

<#
.SYNOPSIS
    Monitors OMS Gateway logs for forbidden domain events and adds allowed domains to the gateway configuration.

.DESCRIPTION
    This script checks the OMS Gateway logs for events indicating forbidden domains.
    If a domain is found in the allowed list, it automatically adds it to the OMS Gateway
    allowed hosts and restarts the service to apply the changes.

.PARAMETER TimeWindowHours
    Number of hours to look back for events. Default is 1 hour.

.PARAMETER LogFolder
    Path to store log files. Default is "$env:ProgramData\OMSGatewayScripts\Logs".

.PARAMETER AllowedDomainsPath
    Path to a text file containing allowed domains. Default is "$env:ProgramData\OMSGatewayScripts\allowed_domains.txt".
    If the file doesn't exist, the script uses a built-in list of allowed domains.

.EXAMPLE
    .\scheduledScriptToCheckForbiddenDomainsAgainstAllowedURLs.ps1
    Runs the script with default parameters.

.EXAMPLE
    .\scheduledScriptToCheckForbiddenDomainsAgainstAllowedURLs.ps1 -TimeWindowHours 24
    Checks for events from the last 24 hours.

.EXAMPLE
    .\scheduledScriptToCheckForbiddenDomainsAgainstAllowedURLs.ps1 -AllowedDomainsPath "C:\Config\allowed_domains.txt"
    Uses a custom file for the allowed domains list.

.NOTES
    This script is intended to be run as a scheduled task.
    It requires administrative privileges to modify the OMS Gateway configuration.
#>

param (
    [Parameter(Mandatory=$false)]
    [int]$TimeWindowHours = 1,

    [Parameter(Mandatory=$false)]
    [string]$LogFolder = "$env:ProgramData\OMSGatewayScripts\Logs",

    [Parameter(Mandatory=$false)]
    [string]$AllowedDomainsPath = "$env:ProgramData\OMSGatewayScripts\allowed_domains.txt"
)

# Enable strict mode to catch common scripting mistakes
Set-StrictMode -Version Latest

# Define error handling preference
$ErrorActionPreference = "Stop"

# Disable confirmation prompts for this session
$ConfirmPreference = 'None'

# Create a log file for script execution
$logFile = "$LogFolder\DomainCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create log directory if it doesn't exist
if (-not (Test-Path -Path $LogFolder)) {
    try {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
        Write-Output "Created log directory: $LogFolder"
    }
    catch {
        Write-Error "Failed to create log directory: $($_.Exception.Message)"
    }
}

# Function for consistent logging
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Write to console with appropriate color
    switch ($Level) {
        "INFO"    { Write-Host $logMessage -ForegroundColor Green }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
    }

    # Write to log file
    try {
        Add-Content -Path $logFile -Value $logMessage -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Define the log name and event ID
$logName = "OMS Gateway Log"
$eventID = 105
$serviceName = "OMSGatewayService"

Write-Log "Script execution started"

# Function to load allowed domains from a file if it exists, otherwise use the default list
function Get-AllowedDomains {
    param (
        [string]$ConfigPath = $AllowedDomainsPath
    )

    # Check if external configuration file exists
    if (Test-Path -Path $ConfigPath) {
        try {
            Write-Log "Loading allowed domains from $ConfigPath"
            $domains = Get-Content -Path $ConfigPath -ErrorAction Stop |
                       Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith('#') } |
                       ForEach-Object { $_.Trim() }

            Write-Log "Loaded $($domains.Count) domains from configuration file"
            return $domains
        }
        catch {
            Write-Log "Error loading domains from $ConfigPath: $($_.Exception.Message)" -Level "ERROR"
            Write-Log "Falling back to default domain list" -Level "WARNING"
        }
    }
    else {
        Write-Log "Configuration file not found at $ConfigPath. Using default domain list." -Level "INFO"
    }

    # Default allowed domains list
    return @(
        "ingest.monitor.azure.com",
        "ods.opinsights.azure.com",
        "handler.control.monitor.azure.com",
        "monitoring.azure.com",
        "global.handler.control.monitor.azure.com",
        "management.azure.com",
        "arcdataservices.com",
        "blob.core.windows.net",
        "guestconfiguration.azure.com",
        "his.arc.azure.com",
        "login.microsoft.com",
        "download.microsoft.com",
        "login.microsoftonline.com",
        "login.windows.net",
        "www.microsoft.com/pkiops/certs",
        "blob.core.windows.net/networkscannerstable/",
        "checkappexec.microsoft.com",
        "delivery.mp.microsoft.com",
        "dm.microsoft.com",
        "download.microsoft.com",
        "download.windowsupdate.com",
        "endpoint.security.microsoft.com",
        "security.microsoft.com",
        "smartscreen.microsoft.com",
        "smartscreen-prod.microsoft.com",
        "update.microsoft.com",
        "urs.microsoft.com",
        "windowsupdate.com",
        "crl.microsoft.com",
        "ctldl.windowsupdate.com",
        "definitionupdates.microsoft.com",
        "go.microsoft.com",
        "wns.windows.com",
        "login.live.com",
        "officecdn-microsoft-com.akamaized.net",
        "packages.microsoft.com",
        "www.microsoft.com/pkiops/",
        "www.microsoft.com/pki/",
        "www.microsoft.com/security/encyclopedia/adlpackages.aspx"
    )
}

# Load the allowed domains
$allowedDomains = Get-AllowedDomains -ConfigPath $AllowedDomainsPath

# Get events from the specified time window to avoid processing older events repeatedly
$timeLimit = (Get-Date).AddHours(-$TimeWindowHours)
Write-Log "Retrieving events since $($timeLimit.ToString('yyyy-MM-dd HH:mm:ss'))"

# Retrieve recent events from OMS Gateway Log with event ID 105
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = $logName;
        ID = $eventID;
        StartTime = $timeLimit
    } -ErrorAction Stop

    $eventCount = $events.Count
    Write-Log "Retrieved $eventCount events with ID $eventID from $logName"
}
catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
    Write-Log "Event log '$logName' not found. Please verify the log exists." -Level "ERROR"
    exit 1
}
catch [System.ArgumentException] {
    # This typically happens when no events match the filter
    Write-Log "No matching events found in the specified time period." -Level "INFO"
    $events = @()
}
catch {
    Write-Log "Error retrieving events: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Initialize counters for summary reporting
$processedCount = 0
$addedCount = 0
$skippedCount = 0
$errorCount = 0

Write-Log "Starting to process events"

foreach ($event in $events) {
    try {
        # Extract the hostname from the event message
        if ($event.Message -match "Target host \((.*?)\) is forbidden") {
            $targetHost = $matches[1].ToLower().Trim()
            $processedCount++

            Write-Log "Processing event for target host: $targetHost"

            # Validate the hostname format
            if (-not ($targetHost -match '^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$')) {
                Write-Log "Invalid hostname format: $targetHost" -Level "WARNING"
                $skippedCount++
                continue
            }

            # Check target host against allowed domains
            $allowed = $false
            $matchedDomain = ""

            foreach ($domain in $allowedDomains) {
                $cleanDomain = $domain.Trim().ToLower()

                if ($targetHost -eq $cleanDomain -or $targetHost.EndsWith(".$cleanDomain")) {
                    $allowed = $true
                    $matchedDomain = $cleanDomain
                    break
                }
            }

            # If allowed, add to OMS Gateway allowed list
            if ($allowed) {
                Write-Log "Host '$targetHost' matches allowed domain '$matchedDomain'"

                # Check if host is already in the allowed list
                try {
                    $existingHosts = Get-Omsgatewayallowedhost -ErrorAction Stop
                    if ($existingHosts -contains $targetHost) {
                        Write-Log "Host '$targetHost' is already in the allowed list" -Level "INFO"
                        $skippedCount++
                        continue
                    }
                }
                catch {
                    Write-Log "Error checking existing allowed hosts: $($_.Exception.Message)" -Level "WARNING"
                    # Continue with the attempt to add the host
                }

                try {
                    # Add the host to the allowed list
                    Add-Omsgatewayallowedhost -Host $targetHost -Confirm:$false -Force -ErrorAction Stop
                    Write-Log "Successfully added '$targetHost' to allowed hosts" -Level "INFO"

                    # Restart the service to apply changes
                    $serviceStatus = Get-Service -Name $serviceName -ErrorAction Stop
                    if ($serviceStatus.Status -eq "Running") {
                        Restart-Service -Name $serviceName -Force -ErrorAction Stop
                        Write-Log "Successfully restarted '$serviceName' service" -Level "INFO"
                    }
                    else {
                        Write-Log "Service '$serviceName' is not running. Starting service..." -Level "WARNING"
                        Start-Service -Name $serviceName -ErrorAction Stop
                        Write-Log "Successfully started '$serviceName' service" -Level "INFO"
                    }

                    $addedCount++
                }
                catch {
                    Write-Log "Failed to add '$targetHost' or restart service: $($_.Exception.Message)" -Level "ERROR"
                    $errorCount++
                }
            }
            else {
                Write-Log "Skipped '$targetHost' (not in allowed domains list)" -Level "INFO"
                $skippedCount++
            }
        }
    }
    catch {
        Write-Log "Error processing event: $($_.Exception.Message)" -Level "ERROR"
        $errorCount++
    }
}

# Write summary information
Write-Log "Script execution completed" -Level "INFO"
Write-Log "Summary: Processed $processedCount events, Added $addedCount hosts, Skipped $skippedCount hosts, Encountered $errorCount errors" -Level "INFO"

# If running in verbose mode, output the log file path
if ($VerbosePreference -eq 'Continue') {
    Write-Verbose "Log file created at: $logFile"
}

# Return a summary object that can be used when the script is called from another script
return [PSCustomObject]@{
    ProcessedCount = $processedCount
    AddedCount = $addedCount
    SkippedCount = $skippedCount
    ErrorCount = $errorCount
    LogFile = $logFile
    TimeWindow = $TimeWindowHours
    ExecutionTime = (Get-Date)
}
