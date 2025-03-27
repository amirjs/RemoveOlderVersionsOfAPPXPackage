<#
. SYNOPSIS Detects vulnerable apps and triggers remediation if vulnerable apps are found.

. DESCRIPTION Detects vulnerable apps and triggers remediation if vulnerable apps are found.

. PARAMETER None

. INPUTS None

. OUTPUTS None

. NOTES
To be used in conjunction with the RemoveOlderVersionsOfPackage remediation script to remove vulnerable apps from the device.
Run as device script in Intune.

.Author "Amir Joseph Sayes"
#>

# Define variables
# This is an array of vulnerable apps with their fixed versions and deprovision status
$VulnerableApps = @(
    [PSCustomObject]@{Name = "Microsoft.HEVCVideoExtension";  FixedVersion = [System.Version]"2.0.61931.0"; Deprovision ="false"}, 
    [PSCustomObject]@{Name = "Microsoft.WindowsTerminal";  FixedVersion = [System.Version]"1.15.2874.0"; Deprovision ="false"}, 
    [PSCustomObject]@{Name = "Microsoft.WebMediaExtensions";  FixedVersion = [System.Version]"1.0.40831.0"; Deprovision ="false"}, 
    [PSCustomObject]@{Name = "Microsoft.VP9VideoExtensions";  FixedVersion = [System.Version]"1.0.61591.0"; Deprovision ="false"},     
    [PSCustomObject]@{Name = "Microsoft.Microsoft3DViewer"; FixedVersion = [System.Version]"7.2307.27042.0"; Deprovision ="false"},
    [PSCustomObject]@{Name = "Microsoft.MSPaint";  FixedVersion = [System.Version]"6.2105.4017.0"; Deprovision ="false"},
    [PSCustomObject]@{Name = "Microsoft.MicrosoftOfficeHub";  FixedVersion = [System.Version]"9999.99.99.99"; Deprovision ="true"},   #Remove all versions and deporvision the app as it's not needed on endpoints
    [PSCustomObject]@{Name = "Microsoft.WindowsMaps";  FixedVersion = [System.Version]"9999.99.99.99"; Deprovision ="true"},   #Remove all versions and deporvision the app as it's not needed on endpoints
    [PSCustomObject]@{Name = "Microsoft.Print3D";  FixedVersion = [System.Version]"9999.99.99.99"; Deprovision ="true"} #According to Nessus scans, the latest version (3.3.791.0) is vulnerable hence setting the fixed version to 8 so the app is removed in all cases 
)

# This is an array to store the vulnerable apps found on the device
$VulnerableAppsFound = @()

# Loop through each app in the VulnerableApps array
foreach ($App in $VulnerableApps) {
    # This is an array to store all vulnerable versions of the current app
    $AllVulnerableVersionsOfTheCurrentApp = @()
    # Get all packages of the current app that have a version less than the fixed version
    $AllVulnerableVersionsOfTheCurrentApp = get-appxpackage -AllUsers -Name $($app.name)  | Select-Object * | Where-Object {[System.Version]$_.version -lt $app.FixedVersion} | Sort-Object name # | Group-Object name    
    # If $AllVulnerableVersionsOfTheCurrentApp is not null that means we found vulnerable version(s) of the app on the device.    
    if ($AllVulnerableVersionsOfTheCurrentApp) {
        # Add found vulnerable packages to the VulnerableAppsFound array
        $VulnerableAppsFound += $AllVulnerableVersionsOfTheCurrentApp        
    }        
}

# Check if any vulnerable apps were found
if ($VulnerableAppsFound) {
    # Loop through each vulnerable app found
    foreach ($VulnerableApp in $VulnerableAppsFound) {
        # Initialize the $Usernames variable
        $Usernames = ""
        # Add a message about the vulnerable app to the output message
        $Usernames = $VulnerableApp.PackageUserInformation.UserSecurityId.Username
        $DetectionOutputMessage += "Vulnerable app found: FullName: $($VulnerableApp.PackageFullName) - Installed for user(s): $($Usernames)"
    }
    # Output the detection message
    Write-Output $DetectionOutputMessage
    # Trigger remediations by exiting with code 1
    exit 1
}
else {
    # If no vulnerable apps were found, output a message saying so
    Write-Output "No vulnerable apps found."
    # Exit with code 0 to indicate that no remediations were triggered
    exit 0
}
