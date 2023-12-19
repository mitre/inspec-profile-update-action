control 'SV-224839' do
  title 'Passwords must be configured to expire.'
  desc 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being discovered or cracked.'
  desc 'check', %q(Review the password never expires status for enabled user accounts.

Open "PowerShell".

Domain Controllers:

Enter "Search-ADAccount -PasswordNeverExpires -UsersOnly | FT Name, PasswordNeverExpires, Enabled".

Exclude application accounts, disabled accounts (e.g., DefaultAccount, Guest), and the krbtgt account.

If any enabled user accounts are returned with a "PasswordNeverExpires" status of "True", this is a finding.

Member servers and standalone or nondomain-joined systems:

Enter 'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount'.

Exclude application accounts and disabled accounts (e.g., DefaultAccount, Guest).

If any enabled user accounts are returned with a "PasswordExpires" status of "False", this is a finding.)
  desc 'fix', 'Configure all enabled user account passwords to expire.

Uncheck "Password never expires" for all enabled user accounts in Active Directory Users and Computers for domain accounts and Users in Computer Management for member servers and standalone or nondomain-joined systems. Document any exceptions with the ISSO.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26530r857233_chk'
  tag severity: 'medium'
  tag gid: 'V-224839'
  tag rid: 'SV-224839r857235_rule'
  tag stig_id: 'WN16-00-000230'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-26518r857234_fix'
  tag 'documentable'
  tag legacy: ['V-73263', 'SV-87915']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
