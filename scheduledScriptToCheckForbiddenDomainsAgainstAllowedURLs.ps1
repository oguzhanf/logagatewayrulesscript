# Disable confirmation prompts for this session
$ConfirmPreference = 'None'

# Define the log name and event ID
$logName = "OMS Gateway Log"
$eventID = 105
$serviceName = "OMSGatewayService"

# Allowed domains list
$allowedDomains = @(
    "<data-collection-endpoint>.<virtual-machine-region-name>.ingest.monitor.azure.com",
    "<log-analytics-workspace-id>.ods.opinsights.azure.com",
    "<virtual-machine-region-name>.handler.control.monitor.azure.com",
    "<virtual-machine-region-name>.monitoring.azure.com",
    "global.handler.control.monitor.azure.com",
    "management.azure.com",
    ".arcdataservices.com",
    ".blob.core.windows.net",
    ".guestconfiguration.azure.com",
    ".his.arc.azure.com",
    "login.microsoft.com",
    "download.microsoft.com",
    "login.microsoftonline.com",
    "login.windows.net",
    "www.microsoft.com/pkiops/certs",
    ".blob.core.windows.net/networkscannerstable/",
    ".checkappexec.microsoft.com",
    ".delivery.mp.microsoft.com",
    ".dm.microsoft.com",
    ".download.microsoft.com",
    ".download.windowsupdate.com",
    ".endpoint.security.microsoft.com",
    ".security.microsoft.com",
    ".smartscreen.microsoft.com",
    ".smartscreen-prod.microsoft.com",
    ".update.microsoft.com",
    ".urs.microsoft.com",
    ".windowsupdate.com",
    "crl.microsoft.com",
    "ctldl.windowsupdate.com",
    "definitionupdates.microsoft.com",
    "go.microsoft.com",
    ".wns.windows.com",
    "login.live.com",
    "officecdn-microsoft-com.akamaized.net",
    "packages.microsoft.com",
    "www.microsoft.com/pkiops/",
    "www.microsoft.com/pki/",
    "www.microsoft.com/security/encyclopedia/adlpackages.aspx"
)

# Get events from the last hour to avoid processing older events repeatedly
$timeLimit = (Get-Date).AddHours(-1)

# Retrieve recent events from OMS Gateway Log with event ID 105
$events = Get-WinEvent -FilterHashtable @{
    LogName = $logName;
    ID = $eventID;
    StartTime = $timeLimit
}

foreach ($event in $events) {
    # Extract the hostname from the event message
    if ($event.Message -match "Target host \((.*?)\) is forbidden") {
        $targetHost = $matches[1].ToLower().Trim()

        # Check target host against allowed domains
        $allowed = $false
        foreach ($domain in $allowedDomains) {
            $cleanDomain = $domain.Trim().ToLower()
            
            if ($targetHost -eq $cleanDomain -or $targetHost.EndsWith($cleanDomain)) {
                $allowed = $true
                break
            }
        }

        # If allowed, add to OMS Gateway allowed list
        if ($allowed) {
            try {
                Add-Omsgatewayallowedhost -Host $targetHost -Confirm:$false -Force
                Restart-Service -Name $serviceName -Force
                Write-Output "$(Get-Date): Added '$targetHost' and restarted '$serviceName'."
            }
            catch {
                Write-Error "$(Get-Date): Failed to add '$targetHost': $_"
            }
        }
        else {
            Write-Output "$(Get-Date): Skipped '$targetHost' (not in allowed domains)."
        }
    }
}
