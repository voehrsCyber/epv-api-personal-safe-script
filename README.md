# epv-api-personal-safe-script
This project should illustrate how to create a personal safe and create a dummy account in it. It also grants User Access to the Cyberark User who is owning this personal account.

Usage is:
.\PersonalAccountCreation.ps1 -PVWAURL <URL> -APIUSER <APIUser> -APIPASSWORD <ApiUserPassword> -CyberarkUser <User for whom the personal safe is created> -TargetAddress <Target Address e.g. domain.org> -TargetUserName <Account name of the account to be created in the safe.>
