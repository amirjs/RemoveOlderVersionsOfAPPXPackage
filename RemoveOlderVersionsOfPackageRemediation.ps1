<#
. SYNOPSIS 
Detects vulnerable apps and triggers remediation if vulnerable apps are found.

. PARAMETER None

. INPUTS None

. OUTPUTS None

. NOTES
To be used in conjunction with the RemoveOlderVersionsOfPackage detection script to remove vulnerable apps from the device.
Run as device script in Intune.

.Author "Amir Joseph Sayes"
#>

#Define variables

# This is a function that we need to use to update the store apps. It's a bit of a hack, but it works.
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

#Start logging
$CurrentTime = Get-Date -Format "dd_MM_yyyy-HH_mm_ss"
Start-Transcript -Path c:\Windows\logs\RemediatingAppxApps_$($env:COMPUTERNAME)_$CurrentTime.log -Force


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

foreach ($App in $VulnerableApps) {
    $AllVulnerableVersionsOfTheCurrentApp = @()
    $AllVulnerableVersionsOfTheCurrentApp = Get-AppxPackage -AllUsers -Name $($app.name)  | Select-Object * | Where-Object {[version]$_.version -lt $app.FixedVersion} | Sort-Object name # | Group-Object name    
    #If $AllVulnerableVersionsOfTheCurrentApp is not null that means we found vulnerable version(s) of the app on the device.    
    if ($AllVulnerableVersionsOfTheCurrentApp) {
        #Now we need to check if a fixed version already exist  
        $FixedVersionsOfTheApp = @() 
        $FixedVersionsOfTheApp = Get-AppxPackage -AllUsers -Name $($app.name)  | Select-Object * | Where-Object {[version]$_.version -ge $App.FixedVersion} | Sort-Object name # | Group-Object name    
        If ($FixedVersionsOfTheApp) {           
            foreach ($FixedVersion in $FixedVersionsOfTheApp ) {
            #Loop and output details about the fix versions that we found
                $Usernames = ""
                # Add a message about the vulnerable app to the output message
                $Usernames = $FixedVersion.PackageUserInformation.UserSecurityId.Username
                $UserSID = $FixedVersion.PackageUserInformation.UserSecurityId.Sid
                Write-Output "A fix version of the app is found: FullName: $($FixedVersion.PackageFullName) - Installed for user(s): $($Usernames)"
            }
        }
        else {
            #####Optional block
            if ($app.Deprovision -eq "true") {
                Write-Output "Skipping trying to update the app $($App.Name) as it's set to be deprovisioned and removed from the device"
            }
            else {
                #If no fixed version is found, trigger a forced update for this app for all users
                $PackageFamilyName = ($AllVulnerableVersionsOfTheCurrentApp | Select-Object -First 1).PackageFamilyName            
                Write-Output "Trying to update the installed version using Windows API.."
                Update-AppxStoreApp -PackageFamilyName $PackageFamilyName
            }
            
            }
        #Now we have done everything we can to make sure a newer version of the app exists, proceed to remove the vulnerable version(s)         
        foreach ($Appx in $AllVulnerableVersionsOfTheCurrentApp) {                              
                #Removal might return an error "failed with error 0x80073D19 - An error occurred because a user was logged off"
                #This happens when the user who installed the app is not logged in, but since we are removing the app for all users, the app gets deleted despite the error
                try {
                    Write-Output "Attempting to remove the app $($Appx.PackageFullName) with version $($Appx.version) for all users gracefully"  
                    Remove-AppxPackage -Package $($Appx.packagefullname) -AllUsers  -ErrorAction Stop  -Verbose -Confirm:$false 
                    Write-Output "Removed: package $($Appx.PackageFullName) with version $($Appx.version) for all users gracefully"                                  
                }
                catch {
                    Write-Output "An error has occurred $($_.Exception.Message)"
                    Write-Output "Could not remove the app for every user  $($($Appx.packagefullname)). Maybe some users don't have it hence the error"                                        
                }                              
            if ("True" -eq $($App.Deprovision)) {
                Try {
                    Write-Output "Deprovioning is set to True. Trying to deporvison the app $($($Appx.packagefullname)) for all users"
                    #Remove-AppxProvisionedPackage -displayname $($App.PackageFullName) -AllUsers -Online -Verbose                         
                    Get-AppxProvisionedPackage -Online | Where-Object {$_.displayname -eq $($App.Name) }  | Remove-AppxProvisionedPackage -Online -AllUsers -Verbose
                }
                catch {
                    #The app wasn't removed. 
                    Write-Output "Could not deprovising or remove the app $($Appx.PackageFullName) with version $($Appx.version) for all users gracefully"  
                }
            }
            #Remove app folder under Program Files\WindowsApps if it exists
            $AppFolder = "C:\Program Files\WindowsApps\$($Appx.packagefullname)"
            if (Test-Path $AppFolder) {
                Write-Output "Removing the app folder $($AppFolder)"
                Remove-Item -Path $AppFolder -Recurse -Force -Verbose
            }
            else {
                Write-Output "The app folder $($AppFolder) does not exist"
            }
        }            
    }        
}
Stop-Transcript


