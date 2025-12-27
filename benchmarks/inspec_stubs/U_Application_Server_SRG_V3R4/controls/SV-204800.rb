control 'SV-204800' do
  title 'The application server must accept Personal Identity Verification (PIV) credentials to access the management interface.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

PIV credentials are only used in an unclassified environment.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as its use as a primary component of layered protection for national security systems.

The application server must support the use of PIV credentials to access the management interface and perform management functions.'
  desc 'check', 'Review application server documentation and configuration to ensure the application server accepts PIV credentials to the management interface.

If PIV credentials are not accepted, this is a finding.'
  desc 'fix', 'Configure the application server to accept PIV credentials to access the management interface.'
  impact 0.7
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4920r283047_chk'
  tag severity: 'high'
  tag gid: 'V-204800'
  tag rid: 'SV-204800r879764_rule'
  tag stig_id: 'SRG-APP-000391-AS-000239'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-4920r283048_fix'
  tag 'documentable'
  tag legacy: ['V-57503', 'SV-71779']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
