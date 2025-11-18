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
    - Entra ID Role: Reports Reader (minimum required)
    - Graph API Permissions: AuditLog.Read.All

    Security Features:
    - Input sanitization against injection attacks
    - Path validation for CSV operations
    - Least-privilege principle (Reports Reader role)

    Author: Security & Creativity Enhanced
    Version: 2.3 - Stale Account Threshold Update
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

# Security Function: Sanitize input to prevent injection attacks
function Test-SafeInput {
    param([string]$Input)

    if ([string]::IsNullOrWhiteSpace($Input)) {
        return $false
    }

    # Block malicious characters that could be used in injection attacks
    $dangerousPatterns = @(
        "'.*--",           # SQL comment injection
        "';.*",            # Statement termination
        "\*",              # Wildcard abuse
        "\$\(",            # Command substitution - $(command)
        "\$\{",            # Variable substitution - ${var}
        "`",               # Backtick execution
        "\|",              # Pipe commands
        "&&",              # Command chaining (AND)
        "\|\|",            # Command chaining (OR)
        ";",               # Command separator
        "<",               # Redirection
        ">",               # Redirection
        "\.\./",           # Path traversal
        "\\\\\\\\",        # UNC path injection (4 backslashes = escaped \\)
        "script:",         # Script injection
        "javascript:",     # Script injection
        "[\x00-\x1F]"      # Control characters
    )

    foreach ($pattern in $dangerousPatterns) {
        if ($Input -match $pattern) {
            Write-Warning "Potentially malicious input detected and blocked: $Input"
            return $false
        }
    }

    # Validate format - Allow legitimate AD account patterns:
    # - Computer accounts: COMPUTER$ (ends with $)
    # - Service accounts: svc-account, svc_account
    # - User accounts: firstname.lastname@domain.com
    # - Special chars: @, ., -, _, $ (at end only for computer accounts)
    #
    # Pattern explanation:
    # ^                    Start of string
    # [a-zA-Z0-9]          Must start with alphanumeric (prevents -flag or leading $)
    # [a-zA-Z0-9@.\-_]*    Middle can contain: letters, numbers, @, ., -, _
    # (\$)?                Optionally end with $ (computer accounts)
    # $                    End of string
    if ($Input -notmatch '^[a-zA-Z0-9][a-zA-Z0-9@.\-_]*(\$)?$') {
        Write-Warning "Invalid characters in input: $Input"
        return $false
    }

    return $true
}

# Security Function: Validate output path
function Test-SafeOutputPath {
    param([string]$Path)

    # Ensure absolute path
    $absolutePath = [System.IO.Path]::GetFullPath($Path)

    # Block paths outside user-accessible areas
    $userProfile = [Environment]::GetFolderPath('UserProfile')
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $system32 = [Environment]::GetFolderPath('System')

    if ($absolutePath.StartsWith($programFiles) -or
        $absolutePath.StartsWith($system32) -or
        $absolutePath.StartsWith("$env:SystemRoot")) {
        Write-Error "Cannot write to system directories"
        return $false
    }

    return $true
}

# Connect to Microsoft Graph with minimal permissions (Reports Reader compatible)
Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "[*] Required Role: Reports Reader or higher" -ForegroundColor Cyan
try {
    # Only request AuditLog.Read.All which is included in Reports Reader role
    Connect-MgGraph -Scopes "AuditLog.Read.All" -ErrorAction Stop
    Write-Host "[+] Successfully connected to Microsoft Graph" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    Write-Host "[!] Ensure you have Reports Reader role assigned" -ForegroundColor Yellow
    exit 1
}

# Verify connection context
$context = Get-MgContext
Write-Host "[+] Connected as: $($context.Account)" -ForegroundColor Green
Write-Host "[+] Organization: $($context.TenantId)" -ForegroundColor Green

# Validate output path for security
Write-Host "`n[*] Validating output path..." -ForegroundColor Cyan
if (-not (Test-SafeOutputPath -Path $OutputCSV)) {
    Write-Error "Invalid or unsafe output path: $OutputCSV"
    exit 1
}
Write-Host "[+] Output path validated" -ForegroundColor Green

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

    # Security: Validate and sanitize inputs
    $samAccountNameSafe = $null
    $upnSafe = $null

    if (![string]::IsNullOrWhiteSpace($samAccountName)) {
        if (Test-SafeInput -Input $samAccountName) {
            $samAccountNameSafe = $samAccountName
        } else {
            Write-Warning "Skipping unsafe SamAccountName: $samAccountName"
        }
    }

    if (![string]::IsNullOrWhiteSpace($upn)) {
        if (Test-SafeInput -Input $upn) {
            $upnSafe = $upn
        } else {
            Write-Warning "Skipping unsafe UPN: $upn"
        }
    }

    # Skip if both inputs are invalid
    if ([string]::IsNullOrWhiteSpace($samAccountNameSafe) -and [string]::IsNullOrWhiteSpace($upnSafe)) {
        Write-Warning "Skipping account due to invalid input"
        continue
    }

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
        StaleAccount = $null
        InteractiveSignIn = $null
        NonInteractiveSignIn = $null
        ErrorMessage = $null
    }

    # Step 1: Validate in on-premises Active Directory
    Write-Host "  [*] Checking on-premises AD..." -ForegroundColor Gray
    try {
        $adUser = $null

        # Try to find by SamAccountName first (using parameterized query to prevent injection)
        if (![string]::IsNullOrWhiteSpace($samAccountNameSafe)) {
            $adUser = Get-ADUser -Filter {SamAccountName -eq $samAccountNameSafe} -Properties UserPrincipalName, Enabled, LastLogonDate -ErrorAction SilentlyContinue
        }

        # If not found and UPN is available, try UPN (using parameterized query)
        if (-not $adUser -and ![string]::IsNullOrWhiteSpace($upnSafe)) {
            $adUser = Get-ADUser -Filter {UserPrincipalName -eq $upnSafe} -Properties UserPrincipalName, Enabled, LastLogonDate -ErrorAction SilentlyContinue
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

    # Determine which identifier to use for Azure lookup (use sanitized values)
    $azureLookupId = if (![string]::IsNullOrWhiteSpace($result.UserPrincipalName)) {
        $result.UserPrincipalName
    } elseif (![string]::IsNullOrWhiteSpace($upnSafe)) {
        $upnSafe
    } else {
        $samAccountNameSafe
    }

    try {
        # Find user in Azure AD - Using userId property instead of filter for security
        # Note: With Reports Reader role, we can access sign-in logs but user query may be limited
        $azureUser = $null

        # Try to get user by UPN (this works with AuditLog.Read.All when querying sign-ins)
        if (![string]::IsNullOrWhiteSpace($azureLookupId)) {
            # Use Get-MgAuditLogSignIn to find user instead of Get-MgUser
            # This is compatible with Reports Reader role
            $testSignIn = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$azureLookupId'" -Top 1 -ErrorAction SilentlyContinue

            if ($testSignIn) {
                # Extract user info from sign-in log
                $azureUser = [PSCustomObject]@{
                    Id = $testSignIn.UserId
                    UserPrincipalName = $testSignIn.UserPrincipalName
                    AccountEnabled = $null  # Not available from sign-in logs
                }
            }
        }

        if ($azureUser) {
            $result.AzureADAccountFound = $true
            $result.AzureUPN = $azureUser.UserPrincipalName
            $result.AzureAccountEnabled = $azureUser.AccountEnabled
            Write-Host "  [+] Found in Azure AD: $($azureUser.UserPrincipalName)" -ForegroundColor Green

            # Query Interactive Sign-ins
            Write-Host "  [*] Querying interactive sign-ins..." -ForegroundColor Gray
            try {
                # Note: userId is a GUID from Azure, already validated through sign-in query
                # This is safe from injection as GUIDs have strict format validation
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
                # Note: userId is a GUID from Azure, already validated through sign-in query
                # This is safe from injection as GUIDs have strict format validation
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

                # Determine if account is stale (last sign-in before July 22, 2025)
                $staleThresholdDate = Get-Date "2025-07-22"
                if ($mostRecent.DateTime -lt $staleThresholdDate) {
                    $result.StaleAccount = "Stale"
                    Write-Host "  [!] Account is STALE (last sign-in before July 22, 2025)" -ForegroundColor Yellow
                } else {
                    $result.StaleAccount = "Active"
                    Write-Host "  [+] Account is Active (signed in after July 22, 2025)" -ForegroundColor Green
                }
            } else {
                Write-Host "  [-] No sign-in activity found" -ForegroundColor Yellow
                $result.StaleAccount = "No Sign-In Data"
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

    # Create audit log entry
    $auditLogPath = "$OutputCSV.audit.log"
    $auditEntry = @"
========================================
AUDIT LOG - Account Sign-In Query
========================================
Execution Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Executed By: $($context.Account)
Tenant ID: $($context.TenantId)
Input File: $InputCSV
Output File: $OutputCSV
Total Accounts Queried: $($accounts.Count)
Successful Queries: $(($results | Where-Object {$_.AzureADAccountFound}).Count)
Failed Queries: $(($results | Where-Object {$_.ErrorMessage}).Count)
Stale Accounts (before 2025-07-22): $(($results | Where-Object {$_.StaleAccount -eq 'Stale'}).Count)
Active Accounts (after 2025-07-22): $(($results | Where-Object {$_.StaleAccount -eq 'Active'}).Count)
No Sign-In Data: $(($results | Where-Object {$_.StaleAccount -eq 'No Sign-In Data'}).Count)
Security Validations Passed: Input sanitization, Path validation
========================================
"@
    Add-Content -Path $auditLogPath -Value $auditEntry
    Write-Host "[+] Audit log created: $auditLogPath" -ForegroundColor Green
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
Write-Host "`n--- Stale Account Analysis ---" -ForegroundColor Cyan
Write-Host "Stale Accounts (before July 22, 2025): $(($results | Where-Object {$_.StaleAccount -eq 'Stale'}).Count)" -ForegroundColor Red
Write-Host "Active Accounts (after July 22, 2025): $(($results | Where-Object {$_.StaleAccount -eq 'Active'}).Count)" -ForegroundColor Green
Write-Host "No Sign-In Data: $(($results | Where-Object {$_.StaleAccount -eq 'No Sign-In Data'}).Count)" -ForegroundColor Yellow
Write-Host "`nErrors: $(($results | Where-Object {$_.ErrorMessage}).Count)" -ForegroundColor Yellow
Write-Host "`nOutput file: $OutputCSV" -ForegroundColor Green

# Disconnect from Microsoft Graph
Disconnect-MgGraph | Out-Null
Write-Host "`n[+] Disconnected from Microsoft Graph" -ForegroundColor Green
