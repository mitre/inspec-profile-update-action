control 'SV-243474' do
  title 'Windows service \\ application accounts with administrative privileges and manually managed passwords,  must have passwords changed at least every 60 days.'
  desc 'NT hashes of passwords for accounts that are not changed regularly are susceptible to reuse by attackers using Pass-the-Hash.  Windows service \\ application account passwords are not typically changed for longer periods of time to ensure availability of the applications.  If a service \\ application also has administrative privileges it will provide elevated access if compromised.'
  desc 'check', 'If no Windows service \\ application accounts with manually managed passwords have administrative privileges, this is NA.

Verify Windows service \\ application accounts with administrative privileges and manually managed passwords, have passwords changed at least every 60 days.'
  desc 'fix', 'If no Windows service \\ application accounts with manually managed passwords have administrative privileges, this is NA.

Change passwords for Windows service \\ application accounts with administrative privileges and manually managed passwords, at least every 60 days.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46749r723455_chk'
  tag severity: 'medium'
  tag gid: 'V-243474'
  tag rid: 'SV-243474r723457_rule'
  tag stig_id: 'AD.0014'
  tag gtitle: 'SRG-OS-000076'
  tag fix_id: 'F-46706r723456_fix'
  tag 'documentable'
  tag legacy: ['V-44059', 'SV-56889']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
