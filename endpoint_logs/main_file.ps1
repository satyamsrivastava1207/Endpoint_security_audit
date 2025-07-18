<#
.SYNOPSIS
    Generates a highly detailed system report in the user-specified format.

.DESCRIPTION
    This script performs a deep scan of a Windows system, collecting specific information about the OS, hardware,
    networking, active connections, and antivirus status. It formats this data into a comprehensive .txt file
    that precisely matches the user-provided blueprint.

    It also saves all the same detailed, multi-line information into a single-row CSV file for data aggregation
    and analysis. Filenames are unique, using the computer's hostname and a timestamp.

.NOTES
    Author: Gemini
    Version: 4.0
    Last Updated: 2024-07-17
#>

# --- Initial Setup ---
Clear-Host
$scriptPath = $PSScriptRoot

# --- Generate dynamic filenames ---
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$baseFileName = Join-Path -Path $scriptPath -ChildPath "$($hostname)_$($timestamp)"
$txtFileName = "$($baseFileName).txt"
$csvFileName = "$($baseFileName).csv"

# --- Main Report Object for CSV Export ---
# Each property will hold the formatted string block for that section.
$csvReportObject = [PSCustomObject]@{
    Hostname                 = $hostname
    Timestamp                = $timestamp
    System_Information       = ""
    CPU_Information          = ""
    RAM_Information          = ""
    Disk_Drive_Information   = ""
    Logical_Volume_Information = ""
    Network_Adapter_Summary  = ""
    IP_Configuration_Detailed = ""
    Active_Listeners         = ""
    Established_Connections  = ""
    Antivirus_Status         = ""
}

# --- Main Execution Block ---
Write-Host "Starting detailed system information scan..." -ForegroundColor Green

# Use an array to build the text file content section by section
$reportContent = @()

# --- System Information ---
Write-Host "Collecting System Information..."
try {
    $compInfo = Get-ComputerInfo -Property "OsName", "OsVersion", "OsHardwareAbstractionLayer", "WindowsProductName", "WindowsInstallationDate", "WindowsBuildLabEx", "CsManufacturer", "CsModel", "CsTotalPhysicalMemory", "CsNumberOfProcessors", "CsProcessorArchitecture", "BiosManufacturer", "BiosVersion", "BiosReleaseDate"
    $sysInfoBlock = $compInfo | Format-List | Out-String
    $reportContent += "--- System Information ---", $sysInfoBlock
    $csvReportObject.System_Information = $sysInfoBlock.Trim()
} catch { Write-Warning "Could not retrieve full Get-ComputerInfo data." }

# --- CPU Information ---
Write-Host "Collecting CPU Information..."
try {
    $cpuInfo = Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, L2CacheSize, L3CacheSize
    $cpuInfoBlock = $cpuInfo | Format-List | Out-String
    $reportContent += "--- CPU Information ---", $cpuInfoBlock
    $csvReportObject.CPU_Information = $cpuInfoBlock.Trim()
} catch { Write-Warning "Could not retrieve CPU data." }

# --- RAM Information ---
Write-Host "Collecting RAM Information..."
try {
    $ramInfo = Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object BankLabel, Capacity, ConfiguredClockSpeed, DeviceLocator, FormFactor, Manufacturer, PartNumber, SerialNumber
    $ramInfoBlock = $ramInfo | Format-Table -AutoSize | Out-String
    $reportContent += "--- RAM Information ---", $ramInfoBlock
    $csvReportObject.RAM_Information = $ramInfoBlock.Trim()
} catch { Write-Warning "Could not retrieve RAM module data." }

# --- Disk Drive Information ---
Write-Host "Collecting Disk Information..."
try {
    $diskInfo = Get-CimInstance -ClassName Win32_DiskDrive | Select-Object Caption, Size, MediaType, Model, SerialNumber
    $diskInfoBlock = $diskInfo | Format-Table -AutoSize | Out-String
    $reportContent += "--- Disk Drive Information ---", $diskInfoBlock
    $csvReportObject.Disk_Drive_Information = $diskInfoBlock.Trim()

    $volumeInfo = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace
    $volumeInfoBlock = $volumeInfo | Format-Table -AutoSize | Out-String
    # This is part of the disk section, so we just append it
    $reportContent += $volumeInfoBlock
    $csvReportObject.Logical_Volume_Information = $volumeInfoBlock.Trim()
} catch { Write-Warning "Could not retrieve Disk/Volume data." }

# --- Network Adapter Details ---
Write-Host "Collecting Network Information..."
try {
    $netAdapterSummary = Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed
    $netAdapterSummaryBlock = $netAdapterSummary | Format-Table -AutoSize | Out-String
    $reportContent += "--- Network Adapter Details ---", $netAdapterSummaryBlock
    $csvReportObject.Network_Adapter_Summary = $netAdapterSummaryBlock.Trim()

    $ipConfigBlocks = foreach ($adapter in $netAdapterSummary) {
        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $adapter.Name -Detailed
        $ipDetails = [PSCustomObject]@{
            "Adapter Name"       = $adapter.Name
            "InterfaceAlias"     = $ipConfig.InterfaceAlias
            "IPv4Address"        = ($ipConfig.IPv4Address.IPAddress -join ', ')
            "IPv4DefaultGateway" = ($ipConfig.IPv4DefaultGateway.NextHop -join ', ')
            "DNSServer"          = ($ipConfig.DNSServer.ServerAddresses -join ', ')
            "MacAddress"         = $adapter.MacAddress
        }
        # Create a formatted block for each adapter
        ($ipDetails | Format-List | Out-String).Trim()
    }
    $ipConfigAllBlocks = $ipConfigBlocks -join "`n`n"
    $reportContent += "--- IP Configuration (Detailed) ---", $ipConfigAllBlocks
    $csvReportObject.IP_Configuration_Detailed = $ipConfigAllBlocks
} catch { Write-Warning "Could not retrieve Network Adapter data." }

# --- Active Network Connections ---
Write-Host "Collecting Active Network Connections..."
try {
    $connections = Get-NetTCPConnection
    $listeners = $connections | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress, LocalPort, OwningProcess, State | Sort-Object -Property LocalPort
    $established = $connections | Where-Object { $_.State -ne 'Listen' } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State | Sort-Object -Property OwningProcess

    $listenersBlock = $listeners | Format-Table -AutoSize | Out-String
    $establishedBlock = $established | Format-Table -AutoSize | Out-String

    $reportContent += "--- Active Network Connections (Open Ports from Host Perspective) ---", $listenersBlock, $establishedBlock
    $csvReportObject.Active_Listeners = $listenersBlock.Trim()
    $csvReportObject.Established_Connections = $establishedBlock.Trim()
} catch { Write-Warning "Could not retrieve network connection data." }

# --- Antivirus Status ---
Write-Host "Collecting Antivirus Status..."
try {
    $avStatus = Get-MpComputerStatus | Select-Object AMProductVersion, AMServiceVersion, AntivirusSignatureVersion, AntivirusEnabled, RealTimeProtectionEnabled, ProductStatus
    $avStatusBlock = $avStatus | Format-List | Out-String
    $reportContent += "--- Antivirus Status (Windows Defender) ---", $avStatusBlock
    $csvReportObject.Antivirus_Status = $avStatusBlock.Trim()
} catch {
    $avError = "Could not get Windows Defender status. It may be disabled or not installed."
    $reportContent += "--- Antivirus Status (Windows Defender) ---", $avError
    $csvReportObject.Antivirus_Status = $avError
    Write-Warning $avError
}

# --- Finalizing Files ---
$reportContent += "--- Script Completed ---"

# --- Export to TXT ---
Write-Host "`nExporting detailed report to TXT file..." -ForegroundColor Green
$reportContent -join "`n`n" | Out-File -FilePath $txtFileName -Encoding UTF8
Write-Host "Successfully created TXT file: $txtFileName"

# --- Export to CSV ---
Write-Host "Exporting detailed report to CSV file..." -ForegroundColor Green
$csvReportObject | Export-Csv -Path $csvFileName -NoTypeInformation -Encoding UTF8
Write-Host "Successfully created CSV file: $csvFileName"

Write-Host "`nScript finished." -ForegroundColor Green
