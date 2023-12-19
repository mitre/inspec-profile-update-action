control 'SV-29396' do
  title 'Windows 2008 passwords must be configured to expire.'
  desc 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being discovered or cracked.'
  desc 'check', %q(Review the password expiration status for enabled user accounts.

PowerShell must be installed on Windows 2008 to run the following.

Open "Windows PowerShell" with elevated privileges (run as administrator).

Domain Controllers:

Enter 'Get-WMIObject -Class Win32_Useraccount -Filter "PasswordExpires=False" | FT Name, PasswordExpires, Disabled, Domain -AutoSize'.

Exclude application accounts and disabled accounts (e.g., Guest).
Domain accounts requiring smart card (CAC/PIV) may also be excluded.

If any enabled user accounts are returned with a "PasswordExpires" status of "False", this is a finding.

Member servers and standalone systems:

Enter 'Get-WMIObject -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount'.

Exclude application accounts and disabled accounts (e.g., Guest).

If any enabled user accounts are returned with a "PasswordExpires" status of "False", this is a finding.

Note: Other queries or tools may be used. The organization must be able to demonstrate the results are valid and meet the intent of the requirement.)
  desc 'fix', 'Configure all enabled user account passwords to expire.

Uncheck "Password never expires" for all enabled user accounts in Active Directory Users and Computers for domain accounts and Users in Computer Management for member servers and standalone systems. Document any exceptions with the ISSO.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-79565r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6840'
  tag rid: 'SV-29396r2_rule'
  tag gtitle: 'Password Expiration'
  tag fix_id: 'F-86703r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
