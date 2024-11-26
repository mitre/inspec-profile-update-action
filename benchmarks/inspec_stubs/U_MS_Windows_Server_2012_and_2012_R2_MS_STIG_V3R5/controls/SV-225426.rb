control 'SV-225426' do
  title 'Windows 2012/2012 R2 accounts must be configured to require passwords.'
  desc 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources.  Accounts on a system must require passwords.'
  desc 'check', %q(Review the password required status for enabled user accounts.

Open "Windows PowerShell".

Domain Controllers:

Enter "Get-ADUser -Filter * -Properties PasswordNotRequired | Where PasswordNotRequired -eq True | FT Name, PasswordNotRequired, Enabled".

Exclude disabled accounts (e.g., Guest) and Trusted Domain Objects (TDOs).

If "PasswordNotRequired" is "True" for any enabled user account, this is a finding.

Member servers and standalone systems:

Enter 'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount'.

Exclude disabled accounts (e.g., Guest).

If any enabled user accounts are returned with a "PasswordRequired" status of "False", this is a finding.)
  desc 'fix', 'Configure all enabled accounts to require passwords.

The password required flag can be set by entering the following on a command line: "Net user [username] /passwordreq:yes", substituting [username] with the name of the user account.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27125r471620_chk'
  tag severity: 'high'
  tag gid: 'V-225426'
  tag rid: 'SV-225426r569185_rule'
  tag stig_id: 'WN12-GE-000015'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-27113r471621_fix'
  tag 'documentable'
  tag legacy: ['V-7002', 'SV-52940']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
