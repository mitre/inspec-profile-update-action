control 'SV-234356' do
  title 'The UEM server must be configured to use a DoD Central Directory Service to provide multifactor authentication for network access to privileged and non-privileged accounts.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MDM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the MDM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos). 

'
  desc 'check', 'Verify the UEM server uses a DoD Central Directory Service to provide multifactor authentication for network access to privileged and non-privileged accounts.

If the UEM server does not use a DoD Central Directory Service to provide multifactor authentication for network access to privileged and non-privileged accounts, this is a finding.'
  desc 'fix', 'Configure the UEM server to use a DoD Central Directory Service to provide multifactor authentication for network access to privileged and non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37541r614078_chk'
  tag severity: 'medium'
  tag gid: 'V-234356'
  tag rid: 'SV-234356r879590_rule'
  tag stig_id: 'SRG-APP-000149-UEM-000083'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-37506r614079_fix'
  tag satisfies: ['FIA \nReference:PP-MDM-414003']
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
