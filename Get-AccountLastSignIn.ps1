<#
.SYNOPSIS
    Retrieves last sign-in information for accounts from both on-premises AD and Azure AD (Entra ID)

.DESCRIPTION
    This script ingests a CSV file containing SamAccountName (Column 1) and UPN (Column 2),
    validates accounts in on-premises Active Directory, then queries Azure AD for both
    interactive and non-interactive sign-in activity. Returns the most recent sign-in with source type.

.PARAMETER InputCSV
    Path to the input CSV file containing account information

.PARAMETER OutputCSV
    Path to the output CSV file for results

.EXAMPLE
    .\Get-AccountLastSignIn.ps1 -InputCSV "C:\accounts.csv" -OutputCSV "C:\SignInReport.csv"

.NOTES
    Requirements:
    - ActiveDirectory PowerShell module (RSAT)
    - Microsoft.Graph PowerShell module
    - Appropriate permissions in Azure AD (AuditLog.Read.All, User.Read.All)

    Author: Security & Creativity Enhanced
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$InputCSV,

    [Parameter(Mandatory = $true)]
    [string]$OutputCSV
)

#Requires -Modules ActiveDirectory, Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Microsoft.Graph.Users

# Import required modules
Write-Host "[*] Importing required modules..." -ForegroundColor Cyan
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Reports -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Write-Host "[+] Modules imported successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import required modules: $_"
    Write-Host "[!] Please install missing modules:" -ForegroundColor Yellow
    Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
    Write-Host "    Install RSAT tools for ActiveDirectory module" -ForegroundColor Yellow
    exit 1
}

# Connect to Microsoft Graph
Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    Connect-MgGraph -Scopes "AuditLog.Read.All", "User.Read.All", "Directory.Read.All" -ErrorAction Stop
    Write-Host "[+] Successfully connected to Microsoft Graph" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Verify connection context
$context = Get-MgContext
Write-Host "[+] Connected as: $($context.Account)" -ForegroundColor Green
Write-Host "[+] Organization: $($context.TenantId)" -ForegroundColor Green

# Import the CSV file
Write-Host "`n[*] Importing CSV file: $InputCSV" -ForegroundColor Cyan
try {
    $accounts = Import-Csv -Path $InputCSV -ErrorAction Stop
    Write-Host "[+] Found $($accounts.Count) accounts to process" -ForegroundColor Green
} catch {
    Write-Error "Failed to import CSV file: $_"
    exit 1
}

# Validate CSV structure
$firstRow = $accounts | Select-Object -First 1
$columns = $firstRow.PSObject.Properties.Name
if ($columns.Count -lt 2) {
    Write-Error "CSV must have at least 2 columns (SamAccountName and UPN)"
    exit 1
}

$samAccountColumn = $columns[0]
$upnColumn = $columns[1]
Write-Host "[+] Using Column 1: $samAccountColumn, Column 2: $upnColumn" -ForegroundColor Green

# Initialize results array
$results = @()
$counter = 0

# Process each account
Write-Host "`n[*] Processing accounts..." -ForegroundColor Cyan
foreach ($account in $accounts) {
    $counter++
    $samAccountName = $account.$samAccountColumn
    $upn = $account.$upnColumn

    Write-Host "`n[$counter/$($accounts.Count)] Processing: $samAccountName" -ForegroundColor Yellow

    # Initialize result object
    $result = [PSCustomObject]@{
        SamAccountName = $samAccountName
        UserPrincipalName = $upn
        ADAccountFound = $false
        ADEnabled = $null
        ADLastLogonDate = $null
        AzureADAccountFound = $false
        AzureUPN = $null
        AzureAccountEnabled = $null
        MostRecentSignIn = $null
        SignInType = $null
        InteractiveSignIn = $null
        NonInteractiveSignIn = $null
        ErrorMessage = $null
    }

    # Step 1: Validate in on-premises Active Directory
    Write-Host "  [*] Checking on-premises AD..." -ForegroundColor Gray
    try {
        $adUser = $null

        # Try to find by SamAccountName first
        if (![string]::IsNullOrWhiteSpace($samAccountName)) {
            $adUser = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -Properties UserPrincipalName, Enabled, LastLogonDate -ErrorAction SilentlyContinue
        }

        # If not found and UPN is available, try UPN
        if (-not $adUser -and ![string]::IsNullOrWhiteSpace($upn)) {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$upn'" -Properties UserPrincipalName, Enabled, LastLogonDate -ErrorAction SilentlyContinue
        }

        if ($adUser) {
            $result.ADAccountFound = $true
            $result.ADEnabled = $adUser.Enabled
            $result.ADLastLogonDate = $adUser.LastLogonDate
            $result.UserPrincipalName = $adUser.UserPrincipalName
            Write-Host "  [+] Found in AD - Enabled: $($adUser.Enabled)" -ForegroundColor Green
        } else {
            Write-Host "  [-] Not found in on-premises AD" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [!] AD Error: $($_.Exception.Message)" -ForegroundColor Red
        $result.ErrorMessage = "AD Error: $($_.Exception.Message)"
    }

    # Step 2: Query Azure AD for sign-in activity
    Write-Host "  [*] Checking Azure AD..." -ForegroundColor Gray

    # Determine which identifier to use for Azure lookup
    $azureLookupId = if (![string]::IsNullOrWhiteSpace($result.UserPrincipalName)) {
        $result.UserPrincipalName
    } elseif (![string]::IsNullOrWhiteSpace($upn)) {
        $upn
    } else {
        $samAccountName
    }

    try {
        # Find user in Azure AD
        $azureUser = Get-MgUser -Filter "userPrincipalName eq '$azureLookupId'" -ErrorAction SilentlyContinue

        if ($azureUser) {
            $result.AzureADAccountFound = $true
            $result.AzureUPN = $azureUser.UserPrincipalName
            $result.AzureAccountEnabled = $azureUser.AccountEnabled
            Write-Host "  [+] Found in Azure AD: $($azureUser.UserPrincipalName)" -ForegroundColor Green

            # Query Interactive Sign-ins
            Write-Host "  [*] Querying interactive sign-ins..." -ForegroundColor Gray
            try {
                $interactiveSignIns = Get-MgAuditLogSignIn -Filter "userId eq '$($azureUser.Id)'" -Top 1 -Sort "createdDateTime DESC" -ErrorAction SilentlyContinue

                if ($interactiveSignIns) {
                    $result.InteractiveSignIn = $interactiveSignIns.CreatedDateTime
                    Write-Host "  [+] Interactive sign-in: $($interactiveSignIns.CreatedDateTime)" -ForegroundColor Green
                }
            } catch {
                Write-Host "  [!] Interactive sign-in query error: $($_.Exception.Message)" -ForegroundColor Red
            }

            # Query Non-Interactive Sign-ins (Service Principal sign-ins)
            Write-Host "  [*] Querying non-interactive sign-ins..." -ForegroundColor Gray
            try {
                $nonInteractiveSignIns = Get-MgAuditLogSignIn -Filter "userId eq '$($azureUser.Id)' and signInEventTypes/any(t: t eq 'nonInteractiveUser')" -Top 1 -Sort "createdDateTime DESC" -ErrorAction SilentlyContinue

                if ($nonInteractiveSignIns) {
                    $result.NonInteractiveSignIn = $nonInteractiveSignIns.CreatedDateTime
                    Write-Host "  [+] Non-interactive sign-in: $($nonInteractiveSignIns.CreatedDateTime)" -ForegroundColor Green
                }
            } catch {
                Write-Host "  [!] Non-interactive sign-in query error: $($_.Exception.Message)" -ForegroundColor Red
            }

            # Determine most recent sign-in
            $signIns = @()
            if ($result.InteractiveSignIn) {
                $signIns += [PSCustomObject]@{
                    DateTime = [DateTime]$result.InteractiveSignIn
                    Type = "Interactive"
                }
            }
            if ($result.NonInteractiveSignIn) {
                $signIns += [PSCustomObject]@{
                    DateTime = [DateTime]$result.NonInteractiveSignIn
                    Type = "Non-Interactive"
                }
            }

            if ($signIns.Count -gt 0) {
                $mostRecent = $signIns | Sort-Object DateTime -Descending | Select-Object -First 1
                $result.MostRecentSignIn = $mostRecent.DateTime
                $result.SignInType = $mostRecent.Type
                Write-Host "  [+] Most recent sign-in: $($mostRecent.DateTime) ($($mostRecent.Type))" -ForegroundColor Cyan
            } else {
                Write-Host "  [-] No sign-in activity found" -ForegroundColor Yellow
            }

        } else {
            Write-Host "  [-] Not found in Azure AD" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [!] Azure AD Error: $($_.Exception.Message)" -ForegroundColor Red
        if ($result.ErrorMessage) {
            $result.ErrorMessage += "; Azure Error: $($_.Exception.Message)"
        } else {
            $result.ErrorMessage = "Azure Error: $($_.Exception.Message)"
        }
    }

    # Add to results
    $results += $result
}

# Export results to CSV
Write-Host "`n[*] Exporting results to: $OutputCSV" -ForegroundColor Cyan
try {
    $results | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Results exported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to export results: $_"
}

# Display summary
Write-Host "`n" -NoNewline
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Accounts Processed: $($results.Count)" -ForegroundColor White
Write-Host "Found in AD: $(($results | Where-Object {$_.ADAccountFound}).Count)" -ForegroundColor White
Write-Host "Found in Azure AD: $(($results | Where-Object {$_.AzureADAccountFound}).Count)" -ForegroundColor White
Write-Host "With Sign-in Activity: $(($results | Where-Object {$_.MostRecentSignIn}).Count)" -ForegroundColor White
Write-Host "Interactive Sign-ins: $(($results | Where-Object {$_.SignInType -eq 'Interactive'}).Count)" -ForegroundColor White
Write-Host "Non-Interactive Sign-ins: $(($results | Where-Object {$_.SignInType -eq 'Non-Interactive'}).Count)" -ForegroundColor White
Write-Host "Errors: $(($results | Where-Object {$_.ErrorMessage}).Count)" -ForegroundColor Yellow
Write-Host "`nOutput file: $OutputCSV" -ForegroundColor Green

# Disconnect from Microsoft Graph
Disconnect-MgGraph | Out-Null
Write-Host "`n[+] Disconnected from Microsoft Graph" -ForegroundColor Green
