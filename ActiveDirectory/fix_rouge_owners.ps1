Function SetObjectOwner{
    Param($OwnerGroup,$ADObject)

    $objpath = "AD:\" + $ADObject.DistinguishedName
    $acl = get-acl -Path $objpath

    $adAccount = New-Object System.Security.Principal.NTAccount (Get-ADDomain -Current LoggedOnUser).DNSRoot,$OwnerGroup
    $acl.SetOwner([Security.Principal.NTaccount]($adAccount))

    set-acl -path $objpath -AclObject $acl
    
}
$baseou = "OU=Tier0,OU=admin,DC=domain,DC=com"

Get-ADObject -SearchBase $baseou -filter * | Where-Object{
    if($_.distinguishedname){Try{$owner = (Get-Acl -Path ("AD:\" + $_.distinguishedname) -ErrorAction Stop).Owner}catch{("AD:\" + $_.distinguishedname)}};
    if($owner -notmatch "Domain Admins|\$"){$_}
} | ForEach-Object{
    if($_.distinguishedname){
        Try{
            $owner = (Get-Acl -Path ("AD:\" + $_.distinguishedname) -ErrorAction Stop).Owner
        }catch{
            ("AD:\" + $_.distinguishedname)
        }
    }

        #SetObjectOwner -OwnerGroup "Domain Admins" -ADObject $_    
        if($_.ObjectClass -match "user|computer|organizationalUnit|group"){
            $Object = New-Object PSObject -Property @{
                distinguishedname    = $_.distinguishedname
                owner                = $owner
                ObjectClass          = $_.ObjectClass
            }
        
            $Object
        }

} #| Out-GridView #| Export-Csv -NoTypeInformation -NoClobber -Path c:\temp\ownerdata.csv -Encoding UTF8 -Append