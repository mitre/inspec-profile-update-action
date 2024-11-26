control 'SV-56889' do
  title 'Windows service \\ application accounts with administrative privileges and manually managed passwords,  must have passwords changed at least every 60 days.'
  desc 'NT hashes of passwords for accounts that are not changed regularly are susceptible to reuse by attackers using Pass-the-Hash.  Windows service \\ application account passwords are not typically changed for longer periods of time to ensure availability of the applications.  If a service \\ application also has administrative privileges it will provide elevated access if compromised.'
  desc 'check', 'If no Windows service \\ application accounts with manually managed passwords have administrative privileges, this is NA.

Verify Windows service \\ application accounts with administrative privileges and manually managed passwords, have passwords changed at least every 60 days.'
  desc 'fix', 'If no Windows service \\ application accounts with manually managed passwords have administrative privileges, this is NA.

Change passwords for Windows service \\ application accounts with administrative privileges and manually managed passwords, at least every 60 days.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-49474r3_chk'
  tag severity: 'medium'
  tag gid: 'V-44059'
  tag rid: 'SV-56889r2_rule'
  tag stig_id: 'AD.0014'
  tag gtitle: 'AD.0014'
  tag fix_id: 'F-49679r4_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
