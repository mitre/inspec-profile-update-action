control 'SV-205658' do
  title 'Windows Server 2019 passwords must be configured to expire.'
  desc 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being discovered or cracked.'
  desc 'check', %q(Review the password never expires status for enabled user accounts.

Open "PowerShell".

Domain Controllers:

Enter "Search-ADAccount -PasswordNeverExpires -UsersOnly | FT Name, PasswordNeverExpires, Enabled".

Exclude application accounts, disabled accounts (e.g., DefaultAccount, Guest) and the krbtgt account.

If any enabled user accounts are returned with a "PasswordNeverExpires" status of "True", this is a finding.

Member servers and standalone or nondomain-joined systems:

Enter 'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount'.

Exclude application accounts and disabled accounts (e.g., DefaultAccount, Guest).

If any enabled user accounts are returned with a "PasswordExpires" status of "False", this is a finding.)
  desc 'fix', 'Configure all enabled user account passwords to expire.

Uncheck "Password never expires" for all enabled user accounts in Active Directory Users and Computers for domain accounts and Users in Computer Management for member servers and standalone or nondomain-joined systems. Document any exceptions with the ISSO.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5923r857295_chk'
  tag severity: 'medium'
  tag gid: 'V-205658'
  tag rid: 'SV-205658r857297_rule'
  tag stig_id: 'WN19-00-000210'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-5923r857296_fix'
  tag 'documentable'
  tag legacy: ['V-93475', 'SV-103561']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
