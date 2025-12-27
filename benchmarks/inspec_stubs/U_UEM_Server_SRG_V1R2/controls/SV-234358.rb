control 'SV-234358' do
  title 'All UEM server local accounts created during application installation and configuration must be removed. 

Note: In this context local accounts refers to user and or administrator accounts on the server that use user name and password for user access and authentication.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MDM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the MDM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos). 

Satisfies:FMT_SMF.1.1(2) b / IA-5(1)(a) 
Reference:PP-MDM-431007'
  desc 'check', 'Verify all UEM server local accounts created during application installation and configuration have been removed. 

Note: In this context "local" accounts refers to user and or administrator accounts on the server that use user name and password for user access and authentication.

If all UEM server local accounts created during application installation and configuration have not been removed, this is a finding.'
  desc 'fix', 'Remove all UEM server local accounts created during application installation. 

Note: In this context "local" accounts refers to user and or administrator accounts on the server that use user name and password for user access and authentication.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37543r614084_chk'
  tag severity: 'medium'
  tag gid: 'V-234358'
  tag rid: 'SV-234358r879592_rule'
  tag stig_id: 'SRG-APP-000151-UEM-000085'
  tag gtitle: 'SRG-APP-000151'
  tag fix_id: 'F-37508r614085_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
