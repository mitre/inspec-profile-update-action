control 'SV-32270' do
  title 'Windows 2008 R2 accounts must be configured to require passwords.'
  desc 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources within the same administrative domain.'
  desc 'check', %q(Review the password required status for enabled user accounts.

Open "Windows PowerShell" with elevated privileges (run as administrator).

Domain Controllers:

Enter "Import-Module ActiveDirectory". (This only needs to be run once during a PowerShell session.)

Enter 'Get-ADUser -Filter * -Properties PasswordNotRequired | Where {$_.PasswordNotRequired -eq "True"} | FT Name, PasswordNotRequired, Enabled -AutoSize'.

Exclude disabled accounts (e.g., Guest).
Domain accounts requiring smart card (CAC/PIV) may also be excluded.

If "PasswordNotRequired" is "True" for any enabled user account, this is a finding.

Member servers and standalone systems:

Enter 'Get-WMIObject -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount -AutoSize'.

Exclude disabled accounts (e.g., Guest).

If any enabled user accounts are returned with a "PasswordRequired" status of "False", this is a finding.

Note: Other queries or tools may be used. The organization must be able to demonstrate the results are valid and meet the intent of the requirement.)
  desc 'fix', 'Configure all enabled accounts to require passwords.

The password required flag can be set by entering the following on a command line: "Net user [username] /passwordreq:yes", substituting [username] with the name of the user account.'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-78969r5_chk'
  tag severity: 'high'
  tag gid: 'V-7002'
  tag rid: 'SV-32270r2_rule'
  tag gtitle: 'Password Requirement'
  tag fix_id: 'F-86127r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
