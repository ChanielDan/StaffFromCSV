<#
AUTHOR  : Daniel Chan 
DATE    : 20-07-2015
COMMENT : This script creates new AD Users and Office365 users
VERSION : 2.51

CHANGELOG
Version 2.51 20-07-15
- Added CSV check
- Added confirmation at end of script run
#>
#----------------------------------------------------------
# LOAD ASSEMBLIES AND MODULES
#----------------------------------------------------------

Try
{
  Import-Module ActiveDirectory -ErrorAction Stop
}
Catch
{
  Write-Host "[ERROR]`t ActiveDirectory Module couldn't be loaded. Script will stop!"
  Exit 1
}

#Variables
$InputCSV = "C:\Scripts\UserCreation\NewStaff.csv"
$OutputCSV = "C:\Scripts\UserCreation\csv\Output.csv"

if (test-path $InputCSV) {$CSV = Import-CSV $InputCSV }
else {Write-Output "$InputCSV doesn't exist, stopping script! Did you enter the correct CSV path?"}


$Credential = Get-Credential -Message "Please enter Office365 Administrative Email and Password"


ForEach ($line in $CSV) {

$givenname = $line.GivenName.Replace(" ","")
$surname = $line.Surname.Replace(" ","")
$samaccountname = $givenname.substring(0,1).ToLower()+$surname.ToLower()
$displayname = "$givenname $surname"
$department = $ine.Department
$OUpath = "OU=Users,OU=Staff,OU=Bitterne Park School,dc=bitterneparkschool,dc=org,dc=uk"
$emailaddress = "$($GivenName).$($Surname)@bitterneparkschool.org.uk"
$FirstName = $givenname.ToLower()
$LastName = $surname.ToLower()

#Generate Random 8 Character long password, 4 letters, 4 numbers, 1 uppercase.
$rand = Get-Random -Maximum 9999
$num = "{0:0000}" -f $rand
Get-Random -Count 4 -InputObject (65..90) | % -begin {$aa=$null} -process {$aa += [char]$_}
$randstring = (Get-Culture).TextInfo.ToTitleCase("$aa".ToLower())
$password = "$randstring$num"

$UPN = "$samaccountname@bitterneparkschool.org.uk"
$homepath = "\\bitterneparkschool.org.uk\staff"

#Create User in AD
New-AdUser -SamAccountName "$samaccountname" -GivenName "$givenname" -Surname "$surname" -name "$displayname" -DisplayName "$displayname" -UserPrincipalName "$UPN" -Path "$OUpath" `
-HomeDrive "Z" -HomeDirectory "$homepath\$samaccountname" -Department "$Department" -ChangePasswordAtLogon $true -AccountPassword (ConvertTo-SecureString -AsPlainText "$password" -Force) -Enabled $true 

#Add AD user to Staff Domain Users
Add-AdGroupMember -Identity "Staff Domain Users" -Members "$samaccountname" 

#Create Folder for Users Home Directory (Z: Drive)
New-Item -Path "$homepath\$samaccountname" -ItemType Directory | Out-Null

#Wait 500ms if the folder directory is not detected, once detected continue script
while (-not (Test-Path -Path "$homepath\$samaccountname"))
{
    Start-Sleep -Milliseconds 500
}

#Check to make sure user has replicated to all DCs before creating ACLs, else will error.

$DCs = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ } | Select -ExpandProperty HostName
        $Passed = $False
        Do {
            $Found = 0
            Foreach ($DC in $DCs) {
                try {
                    $User = Get-ADUser -Identity $samaccountname -Server $DC | Select-Object -ExpandProperty Name
                    $Found += 1
                }
                catch {
                    Start-Sleep -Milliseconds 500
                }
                If ($Found -eq $DCs.Count) {
                    $Passed = $True
                }
            }
        }
        Until ($Passed -eq $True)

#Set Permissions on new folder (Disable inheritance, Full Access to Domain Admins, Modify for user)
$acl = Get-ACL "$homepath\$samaccountname"
$ACL.SetAccessRuleProtection($true, $false)
$ACL.Access | ForEach { [Void]$ACL.RemoveAccessRule($_) }
$ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("$NTDomain\Domain Admins","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")))
$ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("$NTDomain\$samaccountname","Modify", "ContainerInherit, ObjectInherit", "None", "Allow")))
Set-ACL "$homepath\$samaccountname" $ACL

#Generate Email

#Connect to MS Online Service - Enter Admin Credentials

Connect-MsolService -Credential $Credential

#Create new user with Random Password & Office365 Faculty License
New-MsolUser -DisplayName "$displayname" -FirstName "$givenname" -LastName "$surname" -UserPrincipalName "$emailaddress" -LicenseAssignment bitterneparkschoolorg:STANDARDWOFFPACK_IW_FACULTY -UsageLocation GB -Password $password | Out-Null

New-Object -TypeName PSCustomObject -Property @{
    Username = $samaccountname
    EmailAddress = $emailaddress
    Password = $password
} | Export-Csv -Path $OutputCSV -NoTypeInformation -Append

Write-Host "Completed script, see $OutputCSV for user details." 

}



