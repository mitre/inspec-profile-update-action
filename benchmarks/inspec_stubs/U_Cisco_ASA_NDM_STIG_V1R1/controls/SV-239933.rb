control 'SV-239933' do
  title 'The Cisco ASA must be configured to generate audit records when successful/unsuccessful attempts to modify administrator privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco ASA configuration to verify it is compliant with this requirement. The configuration should look similar to the example below.

logging enable
logging buffered informational

Note: The ASA will log all EXEC-mode commands.

If the Cisco ASA is not configured to generate log records when administrator privileges are modified, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to generate log records when account privileges are modified as shown in the example below.

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43166r666160_chk'
  tag severity: 'medium'
  tag gid: 'V-239933'
  tag rid: 'SV-239933r666162_rule'
  tag stig_id: 'CASA-ND-001200'
  tag gtitle: 'SRG-APP-000495-NDM-000318'
  tag fix_id: 'F-43125r666161_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
