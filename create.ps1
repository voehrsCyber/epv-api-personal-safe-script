 Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$username,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$PVWAURL,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$APIUSER,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$APIPASSWORD
    )

$SAFENAME = "personal_" + $username

.\createSafe.ps1 -PVWAURL $PVWAURL -APIUSER $APIUSER -APIPASSWORD $APIPASSWORD -Add -SafeName $SAFENAME
.\createSafe.ps1 -PVWAURL $PVWAURL -APIUSER $APIUSER -APIPASSWORD $APIPASSWORD -Members -SafeName $SAFENAME -UserName $username -MemberRole "Owner"
