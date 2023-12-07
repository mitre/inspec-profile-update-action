control 'SV-225427' do
  title 'Windows 2012/2012 R2 passwords must be configured to expire.'
  desc 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being discovered or cracked.'
  desc 'check', %q(Review the password never expires status for enabled user accounts.

Open "Windows PowerShell" with elevated privileges (run as administrator).

Domain Controllers:

Enter "Search-ADAccount -PasswordNeverExpires -UsersOnly | Where PasswordNeverExpires -eq True | FT Name, PasswordNeverExpires, Enabled".

Exclude application accounts and disabled accounts (e.g., Guest).

If any enabled user accounts are returned with a "PasswordNeverExpires" status of "True", this is a finding.

Member servers and standalone systems:

Enter 'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount'.

Exclude application accounts and disabled accounts (e.g., Guest).

If any enabled user accounts are returned with a "PasswordExpires" status of "False", this is a finding.)
  desc 'fix', 'Configure all enabled user account passwords to expire.

Uncheck "Password never expires" for all enabled user accounts in Active Directory Users and Computers for domain accounts and Users in Computer Management for member servers and standalone systems. Document any exceptions with the ISSO.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27126r857214_chk'
  tag severity: 'medium'
  tag gid: 'V-225427'
  tag rid: 'SV-225427r857215_rule'
  tag stig_id: 'WN12-GE-000016'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-27114r471624_fix'
  tag 'documentable'
  tag legacy: ['V-6840', 'SV-52939']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
