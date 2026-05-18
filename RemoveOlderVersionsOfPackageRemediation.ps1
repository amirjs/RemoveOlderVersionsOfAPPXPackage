<#
.SYNOPSIS 
    Remediates vulnerable Windows AppX packages by updating or removing them from devices.

.DESCRIPTION
    This script performs automated remediation of vulnerable Windows AppX packages (Store apps).
    It implements a multi-strategy approach to ensure device security while preventing service disruption.
    
    EXECUTION FLOWS COVERED:
    
    FLOW 1: NO VULNERABLE VERSIONS FOUND
        - Script checks app → No vulnerable versions exist → Skip to next app
        - Outcome: No action taken
    
    FLOW 2: FIXED VERSION DEPLOYED TO USERS
        - Vulnerable version(s) found → Fixed version exists for real users
        - Action: Remove vulnerable versions
        - Outcome: Only safe versions remain
    
    FLOW 3: FIXED VERSION ONLY STAGED (SYSTEM ACCOUNT)
        - Vulnerable version(s) found → Fixed version only registered to NT AUTHORITY\SYSTEM
        - Action: Trigger Store update to deploy staged version
        - Outcome: Skip removal this run to prevent complete app removal
        - Next Run: Will remediate after fixed version is deployed to users
    
    FLOW 4: NO FIXED VERSION + UPDATE ENABLED (Deprovision=false)
        - Vulnerable version(s) found → No fixed version exists → App should be kept
        - Action: Trigger Store update via Windows API → Remove vulnerable version
        - Outcome: App updated if available, vulnerable version removed
    
    FLOW 5: NO FIXED VERSION + DEPROVISION ENABLED (Deprovision=true)
        - Vulnerable version(s) found → No fixed version exists → App not needed
        - Action: Skip update attempt → Proceed directly to removal and deprovisioning
        - Outcome: App completely removed from device and OS image
    
    FLOW 6: DEPROVISIONING PROCESS
        - Triggered for apps with Deprovision=true after package removal
        - Action: Remove from provisioned packages → Run cleanup routine
        - Outcome: App won't reinstall for new users or during OS updates
    
    SAFETY MECHANISMS:
        - Never removes old version if fixed version is only staged (not deployed)
        - Attempts updates before removal when appropriate
        - Handles partial removal errors gracefully (e.g., user logged off)
        - Comprehensive logging to C:\Windows\logs\

.PARAMETER None
    This script does not accept parameters.

.INPUTS None
    Does not accept pipeline input.

.OUTPUTS None
    All outputs written to transcript log file.

.NOTES
    Prerequisites:
        - Run with administrator privileges
        - Designed for Intune device remediation scripts
        - Requires Windows PowerShell 5.1 for Store update functionality
        - Pair with RemoveOlderVersionsOfPackageDetection.ps1
    
    Log Location:
        C:\Windows\logs\RemediatingAppxApps_<ComputerName>_<Timestamp>.log
    
    Error Handling:
        - Error 0x80073D19 (user logged off) is expected and doesn't indicate failure
        - Store update failures are logged but don't halt execution
        - Deprovisioning errors are caught and logged

.AUTHOR
    Amir Joseph Sayes
#>

#region Helper Functions

<#──────────────────────────────────────────────────────────────────────────────
  FUNCTION: Update-AppxStoreApp
  PURPOSE:  Synchronously updates Windows Store apps using WinRT APIs
  NOTES:    Must run in PowerShell 5.1 due to WinRT API compatibility issues
            Uses Windows.ApplicationModel.Store.Preview.InstallControl APIs
────────────────────────────────────────────────────────────────────────────#>
Function Update-AppxStoreApp {
    <#
    .SYNOPSIS
        Synchronously triggers store updates for a select set of apps. You should run this in
        legacy powershell.exe, as some of the code has problems in pwsh on older OS releases.
    
    .DESCRIPTION
        This function is used to update Windows Store apps. It takes a package family name as input and triggers an update for the corresponding app. The function uses the Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallManager API to perform the update.
        
        Note: It is recommended to run this function in legacy PowerShell (powershell.exe) instead of PowerShell Core (pwsh) on older operating system releases.
    
    .PARAMETER PackageFamilyName
        The package family name of the app to be updated.
    
    .EXAMPLE
        Update-AppxStoreApp -PackageFamilyName "Microsoft.WindowsCalculator_8wekyb3d8bbwe"
    
        This example triggers an update for the Windows Calculator app.
    
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageFamilyName
    )
    
    try
    {
        if ($PSVersionTable.PSVersion.Major -ne 5)
        {
            throw "This script has problems in pwsh on some platforms; please run it with legacy Windows PowerShell (5.1) (powershell.exe)."
        }    
        
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        function Await($WinRtTask, $ResultType) {
            $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
            $netTask = $asTask.Invoke($null, @($WinRtTask))
            $netTask.Wait(-1) | Out-Null
            $netTask.Result
        }

        # https://docs.microsoft.com/uwp/api/windows.applicationmodel.store.preview.installcontrol.appinstallmanager?view=winrt-22000
        # We need to tell PowerShell about this WinRT API before we can call it...
        Write-Host "Enabling Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallManager WinRT type"
        [Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallManager,Windows.ApplicationModel.Store.Preview,ContentType=WindowsRuntime] | Out-Null
        $appManager = New-Object -TypeName Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallManager
        
        # loop through each app and trigger an update
        foreach ($app in $PackageFamilyName)
        {
            try
            {
                Write-Host "Requesting an update for $app..."
                $updateOp = $appManager.UpdateAppByPackageFamilyNameAsync($app)
                $updateResult = Await $updateOp ([Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallItem])
                $timeout = 60
                while ($true)
                {
                    if ($null -eq $updateResult)
                    {
                        Write-Host "Update is null. It must already be completed (or there was no update)..."
                        break
                    }
    
                    if ($null -eq $updateResult.GetCurrentStatus())
                    {
                        Write-Host "Current status is null. WAT"
                        break
                    }
    
                    Write-Host $updateResult.GetCurrentStatus().PercentComplete
                    if ($updateResult.GetCurrentStatus().PercentComplete -eq 100)
                    {
                        Write-Host "Install completed ($app)"
                        break
                    }
                    Start-Sleep -Seconds 3
                    $timeout -= 3
                    Write-Output "Seconds remaining before timeout: $timeout"
                    if ($timeout -le 0)
                    {
                        Write-Host "Update timed out after 60 seconds"
                        break
                    }
                }
            }
            catch [System.AggregateException]
            {
                # If the thing is not installed, we can't update it. In this case, we get an
                # ArgumentException with the message "Value does not fall within the expected
                # range." I cannot figure out why *that* is the error in the case of "app is
                # not installed"... perhaps we could be doing something different/better, but
                # I'm happy to just let this slide for now.
                $problem = $_.Exception.InnerException # we'll just take the first one
                Write-Host "Error updating app $app : $problem"
                Write-Host "(this is expected if the app is not installed; you can probably ignore this)"
            }
            catch
            {
                Write-Host "Unexpected error updating app $app : $_"
            }
        }
    
        Write-Host "Store updates completed"
    
    }
    catch
    {
        Write-Error "Problem updating store apps: $_"
    }
    
}

#endregion

#region Main Script Execution

<#──────────────────────────────────────────────────────────────────────────────
  SECTION: LOGGING INITIALIZATION
  PURPOSE: Start transcript logging for audit trail and troubleshooting
────────────────────────────────────────────────────────────────────────────#>
#Start logging
$CurrentTime = Get-Date -Format "dd_MM_yyyy-HH_mm_ss"
Start-Transcript -Path c:\Windows\logs\RemediatingAppxApps_$($env:COMPUTERNAME)_$CurrentTime.log -Force

<#──────────────────────────────────────────────────────────────────────────────
  SECTION: VULNERABLE APPS CONFIGURATION
  
  Each app entry defines:
    - Name:         Package name prefix to match (e.g., "Microsoft.WebMediaExtensions")
    - FixedVersion: Minimum safe version; anything below is considered vulnerable
    - Deprovision:  "true" = completely remove app from device and OS image
                    "false" = update to safe version if possible
  
  SPECIAL VERSION VALUES:
    - 9999.99.99.99 = Remove ALL versions (app not needed on endpoints)
  
  DEPROVISION BEHAVIOR:
    - "true"  = Remove package + Remove from provisioned packages + Prevent reinstall
    - "false" = Attempt update first, then remove vulnerable version only
────────────────────────────────────────────────────────────────────────────#>
$VulnerableApps = @(
    [PSCustomObject]@{Name = "Microsoft.WebMediaExtensions";  FixedVersion = [System.Version]"1.0.40831.0"; Deprovision ="false"}, 
    [PSCustomObject]@{Name = "Microsoft.VP9VideoExtensions";  FixedVersion = [System.Version]"1.0.42791.0"; Deprovision ="false"},     
    [PSCustomObject]@{Name = "Microsoft.Microsoft3DViewer"; FixedVersion = [System.Version]"7.2307.27042.0"; Deprovision ="false"},
    [PSCustomObject]@{Name = "Microsoft.HEIFImageExtension"; FixedVersion = [System.Version]"1.0.43012.0"; Deprovision ="false"},
    [PSCustomObject]@{Name = "Microsoft.HEVCVideoExtension"; FixedVersion = [System.Version]"2.1.61661.0"; Deprovision ="false"},
    [PSCustomObject]@{Name = "Microsoft.MSPaint";  FixedVersion = [System.Version]"6.2305.16087.0"; Deprovision ="true"},    
    [PSCustomObject]@{Name = "Microsoft.WindowsMaps";  FixedVersion = [System.Version]"9999.99.99.99"; Deprovision ="true"},   #Remove all versions and deprovision the app as it's not needed on endpoints
    [PSCustomObject]@{Name = "Microsoft.Print3D";  FixedVersion = [System.Version]"9999.99.99.99"; Deprovision ="true"}, #According to Nessus scans, the latest version (3.3.791.0) is vulnerable hence setting the fixed version to 8 so the app is removed in all cases 
    [PSCustomObject]@{Name = "Microsoft.WindowsTerminal";  FixedVersion = [System.Version]"1.15.2874"; Deprovision ="false"},
    [PSCustomObject]@{Name = "Microsoft.RawImageExtension";  FixedVersion = [System.Version]"2.1.61661.0"; Deprovision ="false"},
    [PSCustomObject]@{Name = "MicrosoftTeams";  FixedVersion = [System.Version]"99999.9999.9999.9999"; Deprovision ="true"}, # Removes Teams Personal    
    [PSCustomObject]@{Name = "Microsoft.WindowsNotepad";  FixedVersion = [System.Version]"11.2510.14.0"; Deprovision ="true"} # Notepad 
    
    
)

<#──────────────────────────────────────────────────────────────────────────────
  SECTION: MAIN REMEDIATION LOOP
  PURPOSE: Iterate through each vulnerable app definition and remediate as needed
────────────────────────────────────────────────────────────────────────────#>
foreach ($App in $VulnerableApps) {
    
    # ─── STEP 1: IDENTIFY VULNERABLE VERSIONS ───
    # Query all installed instances of this app across all users
    # Filter to versions below the fixed version threshold
    $AllVulnerableVersionsOfTheCurrentApp = @()
    $AllVulnerableVersionsOfTheCurrentApp = Get-AppxPackage -AllUsers -Name $($app.name)  | Select-Object * | Where-Object {[version]$_.version -lt $app.FixedVersion} | Sort-Object name # | Group-Object name    
    
    # ─── DECISION POINT 1: Are vulnerable versions present? ───
    # YES → Continue to remediation logic below
    # NO  → Skip to next app (FLOW 1)
    #If $AllVulnerableVersionsOfTheCurrentApp is not null that means we found vulnerable version(s) of the app on the device.    
    if ($AllVulnerableVersionsOfTheCurrentApp) {
        
        # ─── STEP 2: CHECK FOR FIXED VERSIONS ───
        # Query for versions at or above the fixed version threshold
        # Determines if a safe version is already available on the device
        #Now we need to check if a fixed version already exist  
        $FixedVersionsOfTheApp = @() 
        $FixedVersionsOfTheApp = Get-AppxPackage -AllUsers -Name $($app.name)  | Select-Object * | Where-Object {[version]$_.version -ge $App.FixedVersion} | Sort-Object name # | Group-Object name    
        
        # Safety flag: Controls whether vulnerable versions can be removed
        # Set to $false if fixed version is only staged (prevents leaving app completely uninstalled)
        $SafeToRemove = $true
        
        # ─── DECISION POINT 2: Does a fixed version exist? ───
        # YES → Validate deployment status (STEP 3)
        # NO  → Determine update strategy (STEP 4)
        If ($FixedVersionsOfTheApp) {           
            foreach ($FixedVersion in $FixedVersionsOfTheApp ) {
            #Loop and output details about the fix versions that we found
                $Usernames = ""
                # Add a message about the vulnerable app to the output message
                $Usernames = $FixedVersion.PackageUserInformation.UserSecurityId.Username
                $UserSID = $FixedVersion.PackageUserInformation.UserSecurityId.Sid
                Write-Output "A fix version of the app is found: FullName: $($FixedVersion.PackageFullName) - Installed for user(s): $($Usernames)"
            }
            
            # ─── STEP 3: VALIDATE FIXED VERSION DEPLOYMENT STATUS ───
            # CRITICAL SAFETY CHECK:
            # A fixed version returned by Get-AppxPackage may only be *staged* (registered for NT AUTHORITY\SYSTEM),
            # meaning Windows Update has downloaded it but not yet deployed it to real users.
            # Removing the old version with -AllUsers in this state also clears the staged entry,
            # leaving no version of the app installed for any user.
            # Only allow removal if the fixed version is actually deployed to at least one real (non-SYSTEM) user.
            #
            # FLOW 3 (STAGED ONLY): Fixed version for SYSTEM only → Trigger update → Skip removal → Remediate next run
            # FLOW 2 (DEPLOYED):    Fixed version for real users → Continue to removal
            $FixedVersionDeployedToUsers = @($FixedVersionsOfTheApp | Where-Object {
                @($_.PackageUserInformation.UserSecurityId | Where-Object { $_.Username -and $_.Username -ne 'NT AUTHORITY\SYSTEM' }).Count -gt 0
            })
            if ($FixedVersionDeployedToUsers.Count -eq 0 -and $app.Deprovision -ne "true") {
                # *** FLOW 3: FIXED VERSION ONLY STAGED ***
                # Fixed version exists but only for SYSTEM account
                # ACTION: Trigger Store update → Set SafeToRemove=$false → Skip removal this run
                # NEXT RUN: After deployment to users, removal will proceed
                Write-Output "WARNING: Fixed version of $($App.Name) is only staged (registered for NT AUTHORITY\SYSTEM) and has not been deployed to real users yet. Triggering a Store update to deploy the staged version, then skipping removal for this run to avoid leaving the app fully uninstalled. It will be removed on the next remediation run once the new version is properly deployed."
                $PackageFamilyName = ($AllVulnerableVersionsOfTheCurrentApp | Select-Object -First 1).PackageFamilyName
                Update-AppxStoreApp -PackageFamilyName $PackageFamilyName
                $SafeToRemove = $false
            }
            # else: *** FLOW 2: FIXED VERSION DEPLOYED TO USERS ***
            # Fixed version exists for real users → Safe to proceed with removal
        }
        else {
            # ─── STEP 4: NO FIXED VERSION EXISTS - DETERMINE UPDATE STRATEGY ───
            # Two paths based on Deprovision setting:
            # FLOW 5: Deprovision=true  → Skip update, proceed to removal
            # FLOW 4: Deprovision=false → Attempt Store update, then remove
            
            #####Optional block
            if ($app.Deprovision -eq "true") {
                # *** FLOW 5: NO FIXED VERSION + DEPROVISION ENABLED ***
                # App is marked for complete removal
                # ACTION: Skip update attempt → Proceed directly to removal and deprovisioning
                Write-Output "Skipping trying to update the app $($App.Name) as it's set to be deprovisioned and removed from the device"
            }
            else {
                # *** FLOW 4: NO FIXED VERSION + UPDATE ENABLED ***
                # App should be kept if possible
                # ACTION: Attempt Store update → Then remove vulnerable version
                #If no fixed version is found, trigger a forced update for this app for all users
                $PackageFamilyName = ($AllVulnerableVersionsOfTheCurrentApp | Select-Object -First 1).PackageFamilyName            
                Write-Output "Trying to update the installed version using Windows API.."
                Update-AppxStoreApp -PackageFamilyName $PackageFamilyName
            }
            
            }
        
        # ─── STEP 5: REMOVAL DECISION GATE ───
        # Check $SafeToRemove flag (set to $false in FLOW 3 when fixed version is staged only)
        # If $false → Skip removal, continue to next app
        # If $true  → Proceed to removal (FLOWS 2, 4, 5)
        #Now we have done everything we can to make sure a newer version of the app exists, proceed to remove the vulnerable version(s)         
        if (-not $SafeToRemove) { continue }
        
        # ─── STEP 6: REMOVE VULNERABLE VERSIONS ───
        # Iterate through each vulnerable version and remove for all users
        foreach ($Appx in $AllVulnerableVersionsOfTheCurrentApp) {                              
                # EXPECTED ERROR HANDLING:
                # Error 0x80073D19 ("user was logged off") is EXPECTED and NORMAL
                # Occurs when the user who installed the app is not currently logged in
                # The -AllUsers flag ensures removal succeeds across all user contexts despite the error
                #Removal might return an error "failed with error 0x80073D19 - An error occurred because a user was logged off"
                #This happens when the user who installed the app is not logged in, but since we are removing the app for all users, the app gets deleted despite the error
                try {
                    Write-Output "Attempting to remove the app $($Appx.PackageFullName) with version $($Appx.version) for all users gracefully"  
                    Remove-AppxPackage -Package $($Appx.packagefullname)  -AllUsers  -ErrorAction Stop  -Verbose -Confirm:$false 
                    Write-Output "Removed: package $($Appx.PackageFullName) with version $($Appx.version) for all users gracefully"                                  
                }
                catch {
                    Write-Output "An error has occurred $($_.Exception.Message)"
                    Write-Output "Could not remove the app for every user  $($($Appx.packagefullname)). Maybe some users don't have it hence the error"                                        
                }
                
            # ─── STEP 7: DEPROVISIONING (FLOW 6) ───
            # Only executed if Deprovision="true" for this app
            # Removes app from OS provisioning store to prevent:
            #   - Automatic installation for new users
            #   - Re-deployment during OS updates  
            #   - App appearing in default Start menu
            # Also triggers cleanup of orphaned provisioned packages
            if ("True" -eq $($App.Deprovision)) {
                # *** FLOW 6: DEPROVISIONING PROCESS ***
                Try {
                    Write-Output "Deprovioning is set to True. Trying to deporvison the app $($($Appx.packagefullname)) for all users"
                    #Remove-AppxProvisionedPackage -displayname $($App.PackageFullName) -AllUsers -Online -Verbose                         
                    Get-AppxProvisionedPackage -Online | Where-Object {$_.displayname -eq $($App.Name) -and [System.Version]$_.Version -lt $App.FixedVersion}  | Remove-AppxProvisionedPackage -Online -AllUsers -Verbose
                    # trigger this to clean up orphaned provisioned packages 	c:\windows\system32\rundll32.exe AppxDeploymentClient.dll,AppxCleanupOrphanPackages
                    Start-Process -FilePath "c:\windows\system32\rundll32.exe" -ArgumentList "AppxDeploymentClient.dll,AppxCleanupOrphanPackages" -Wait -NoNewWindow -ErrorAction SilentlyContinue 
                }
                catch {
                    #The app wasn't removed. 
                    Write-Output "Could not deprovising or remove the app $($Appx.PackageFullName) with version $($Appx.version) for all users gracefully"  
                }
            }            
        }            
    }
    else {
        # *** FLOW 1: NO VULNERABLE VERSIONS FOUND ***
        # App is either not installed or only safe versions are present
        # ACTION: Skip to next app in array
    }        
}

<#──────────────────────────────────────────────────────────────────────────────
  SECTION: SCRIPT COMPLETION
  PURPOSE: Stop transcript logging
────────────────────────────────────────────────────────────────────────────#>
Stop-Transcript

#endregion


