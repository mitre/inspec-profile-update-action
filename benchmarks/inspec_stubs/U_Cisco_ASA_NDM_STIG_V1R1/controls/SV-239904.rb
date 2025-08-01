control 'SV-239904' do
  title 'The Cisco ASA must be configured to generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement. The configuration should look similar to the example below:

logging enable
logging buffered informational

Note: The ASA will log all login attempts as well as the name of the user entering the enable command.

If the Cisco ASA is not configured to generate audit records when successful/unsuccessful attempts to logon, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA as shown in the example below.

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43137r666073_chk'
  tag severity: 'medium'
  tag gid: 'V-239904'
  tag rid: 'SV-239904r666075_rule'
  tag stig_id: 'CASA-ND-000240'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-43096r666074_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
