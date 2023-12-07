control 'SV-205700' do
  title 'Windows Server 2019 accounts must require passwords.'
  desc 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources. Accounts on a system must require passwords.'
  desc 'check', %q(Review the password required status for enabled user accounts.

Open "PowerShell".

Domain Controllers:

Enter "Get-Aduser -Filter * -Properties Passwordnotrequired |FT Name, Passwordnotrequired, Enabled".

Exclude disabled accounts (e.g., DefaultAccount, Guest) and Trusted Domain Objects (TDOs).

If "Passwordnotrequired" is "True" or blank for any enabled user account, this is a finding.

Member servers and standalone or nondomain-joined systems:

Enter 'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount'.

Exclude disabled accounts (e.g., DefaultAccount, Guest).

If any enabled user accounts are returned with a "PasswordRequired" status of "False", this is a finding.)
  desc 'fix', 'Configure all enabled accounts to require passwords.

The password required flag can be set by entering the following on a command line: "Net user [username] /passwordreq:yes", substituting [username] with the name of the user account.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5965r857293_chk'
  tag severity: 'medium'
  tag gid: 'V-205700'
  tag rid: 'SV-205700r857294_rule'
  tag stig_id: 'WN19-00-000200'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-5965r355019_fix'
  tag 'documentable'
  tag legacy: ['SV-103525', 'V-93439']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
