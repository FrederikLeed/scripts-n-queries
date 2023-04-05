<#
.SYNOPSIS
    This script automates the process of creating a new user account and group for joining machines to a Windows Active Directory domain.

.DESCRIPTION
    The script performs the following tasks:

    1. Creates a new service account with a specified name and path, and sets the password as provided by the user.
    2. Creates a new security group with a specified name and path, and adds a description indicating the group's purpose.
    3. Adds the service account to the security group.
    4. Delegates the necessary permissions on the specified Organizational Unit (OU) to the security group, allowing its members to join machines to the domain.
    5. Sets the ms-ds-MachineAccountQuota to 0 to prevent other users from joining machines to the domain.

    The script includes error handling and logging to ensure smooth execution and provide useful information on the process.

.PARAMETER TargetOUDN
    The Distinguished Name (DN) of the target Organizational Unit (OU) where the permissions will be delegated.

.PARAMETER GroupName
    The name of the new security group that will be created.

.PARAMETER GroupPath
    The LDAP path where the new security group will be created.

.PARAMETER ServiceAccountName
    The name of the new service account that will be created.

.PARAMETER ServiceAccountPath
    The LDAP path where the new service account will be created.

.EXAMPLE
    .\CreateUserAndGroupForDomainJoin.ps1 -TargetOUDN "OU=Workstations,DC=example,DC=com" -GroupName "DomainJoinGroup" -GroupPath "OU=Groups,DC=example,DC=com" -ServiceAccountName "DomainJoinServiceAccount" -ServiceAccountPath "OU=ServiceAccounts,DC=example,DC=com"

    This example creates a new service account named "DomainJoinServiceAccount" in the "OU=ServiceAccounts,DC=example,DC=com" container, a new security group named "DomainJoinGroup" in the "OU=Groups,DC=example,DC=com" container, and delegates the necessary permissions on the "OU=Workstations,DC=example,DC=com" OU to the security group.
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,Position=0)]
    [string]$TargetOUDN,
    [Parameter(Mandatory=$true,Position=1)]
    [String]$GroupName,
    [Parameter(Mandatory=$false,Position=2)]
    [String]$GroupPath,
    [Parameter(Mandatory=$true,Position=3)]
    [String]$ServiceAccountName,
    [Parameter(Mandatory=$false,Position=4)]
    [String]$ServiceAccountPath
)
Begin{

# Function definitions
function Set-DomainJoinPermissions($groupsid, $ou){
    #http://support.microsoft.com/kb/932455
    # Create Computer Accounts
    # Delete Computer Accounts
    # Reset Password
    # Read and write Account Restrictions
    # Validated write to DNS host name 
    # Validated write to service principal name
    Add-Log -LogEntry ("Setting Domain Join Permissions on:" + $ou)

    Try {
        $Error.Clear()
        $ace1 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"CreateChild,DeleteChild","Allow",$computerguid
        $ace2 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"ExtendedRight","Allow",$extendedrightsmap["Reset Password"],"Descendents",$computerguid
        $ace3 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"readproperty,writeproperty","Allow",$extendedrightsmap["Account Restrictions"],"Descendents",$computerguid
        $ace4 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"writeproperty","Allow",$extendedrightsmap["DNS Host Name Attributes"],"Descendents",$computerguid
        $ace5 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"writeproperty","Allow",$spnguid,"Descendents",$computerguid

        $acl = Get-ACL -Path ("AD:\"+$ou)
        $acl.AddAccessRule($ace1)
        $acl.AddAccessRule($ace2)
        $acl.AddAccessRule($ace3)
        $acl.AddAccessRule($ace4)
        $acl.AddAccessRule($ace5)
        Set-ACL -ACLObject $acl -Path ("AD:\"+$ou)
        
        } 
        Catch {
            write-host "Caught an exception:" -ForegroundColor Red
            write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
            write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
        }
}
    function Add-Log{
        param
        (
        $LogEntry
        )
        if ( $LogEntry )
        {
            write-debug $LogEntry
            ((get-date).tostring("yyyy-MM-dd hh:mm ") + $LogEntry) | out-file .\$Logfilename.log -append
        }

    }
}
Process{

# Initialize current environment variables
    $Logfilename = $MyInvocation.MyCommand.Name
    $rootdse = Get-ADRootDSE
    $extendedrightsmap = @{} 
    Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid | ForEach-Object {$extendedrightsmap[$_.displayName]=[System.GUID]$_.rightsGuid}
    $spnguid = [System.Guid](Get-ADObject -Identity ("CN=Service-Principal-Name," + $rootdse.SchemaNamingContext) -Properties schemaIDGUID).schemaIDGUID
    $computerguid = [System.Guid](Get-ADObject -Identity ("CN=Computer," + $rootdse.SchemaNamingContext) -Properties schemaIDGUID).schemaIDGUID
    $domain = Get-ADDomain
    $domainName = $domain.DNSRoot


# Prevent normal users from adding machines to the domain by setting ms-DS-MachineAccountQuota to 0

    Add-Log -LogEntry ("Setting the ms-ds-MachineAccountQuota to 0")
    Set-ADDomain $domainName -Replace @{"ms-ds-MachineAccountQuota"="0"}

# Create Group

    Try {
        $Error.Clear()
        If(Get-ADGroup $groupname) {
            #write-host "The Group already exists" -Fore Yellow
            Add-Log -LogEntry ("The group already exists: " + $groupname)
        }
    } #already exists
    Catch 
    {
        If($Error[0].FullyQualifiedErrorID -eq "ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.GetADGroup")
        {
            If($GroupPath){
                New-ADGroup -Name $GroupName -SamAccountName $GroupName -GroupCategory Security -GroupScope DomainLocal -DisplayName $GroupName -Path $GroupPath -Description "Members of this group can join computers to the domain"  -Server $rootdse.dnsHostName
                If(Get-ADGroup $GroupName -Server $rootdse.dnsHostName){
                    Add-Log -LogEntry ("The group created: " + $groupname)
                }
            }else{
                throw "Delegation group does not exist and Group cannot be created since GroupPath is not specified."
            }
        }
    }

# Create Service Account

    Try {
        $Error.Clear()
        If(Get-ADUser $ServiceAccountName) {
            #write-host "The user already exists" -Fore Yellow
            Add-Log -LogEntry ("The user already exists: " + $ServiceAccountName)
            }
    } #already exists
    Catch 
    {
        If($Error[0].FullyQualifiedErrorID -eq "ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.GetADUser")
        {
            If($ServiceAccountPath){
                New-ADUser -SamAccountName $ServiceAccountName -Name $ServiceAccountName -Path $ServiceAccountPath -AccountPassword (Read-Host -AsSecureString "AccountPassword") -CannotChangePassword $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true -Enabled $true -Description "Service Accounts with delegated permissions to join computers to the domain" -Server $rootdse.dnsHostName
                If(Get-ADUser $ServiceAccountName  -Server $rootdse.dnsHostName){
                    Add-Log -LogEntry ("The account created: " + $ServiceAccountName)
                }
            }else{
                throw "Service Account does not exist and Service Account cannot be created since ServiceAccountPath is not specified."
            }
        }
    }

# Add the User to the Group

    $group =Get-ADGroup $GroupName
    $user=Get-ADUser $ServiceAccountName
    Add-ADGroupMember $group -Members $user

# Set Permissions on the OUs

    $groupsid = new-object System.Security.Principal.SecurityIdentifier $group.SID

    $ou = $TargetOUDN
    Set-DomainJoinPermissions $groupsid $ou
}
End{}