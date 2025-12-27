control 'SV-239934' do
  title 'The Cisco ASA must be configured to generate audit records when successful/unsuccessful attempts to delete administrator privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco ASA configuration to verify it is compliant with this requirement. The configuration should look similar to the example below.

logging enable
logging buffered informational

Note: The ASA will log all EXEC-mode commands.

If the Cisco ASA is not configured to generate log records when administrator privileges are deleted, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to generate log records when administrator privileges are deleted as shown in the example below.

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43167r666163_chk'
  tag severity: 'medium'
  tag gid: 'V-239934'
  tag rid: 'SV-239934r879870_rule'
  tag stig_id: 'CASA-ND-001210'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-43126r666164_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
