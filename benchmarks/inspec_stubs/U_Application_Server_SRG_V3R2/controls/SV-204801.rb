control 'SV-204801' do
  title 'The application server must electronically verify Personal Identity Verification (PIV) credentials for access to the management interface.'
  desc 'The use of Personal Identity Verification (PIV) credentials facilitates standardization and reduces the risk of unauthorized access.

PIV credentials are only used in an unclassified environment.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as its use as a primary component of layered protection for national security systems.

The application server must electronically verify the use of PIV credentials to access the management interface and perform management functions.'
  desc 'check', 'Review application server documentation and configuration to ensure the application server electronically verifies PIV credentials to the management interface.

If PIV credentials are not electronically verified, this is a finding.'
  desc 'fix', 'Configure the application server to electronically verify PIV credentials to access the management interface.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4921r283050_chk'
  tag severity: 'medium'
  tag gid: 'V-204801'
  tag rid: 'SV-204801r508029_rule'
  tag stig_id: 'SRG-APP-000392-AS-000240'
  tag gtitle: 'SRG-APP-000392'
  tag fix_id: 'F-4921r283051_fix'
  tag 'documentable'
  tag legacy: ['V-57505', 'SV-71781']
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end
