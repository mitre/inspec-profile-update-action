control 'SV-239907' do
  title 'The Cisco ASA must be configured to produce audit records containing information to establish where the events occurred.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as device hardware components, device software modules, session identifiers, filenames, host names, and functionality.

Associating information about where the event occurred within the network device provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement. The configuration should look similar to the example below.

logging enable
logging buffered informational

Note: The ASA will log location (IP address or console) from where configuration commands are entered. 

If the ASA is not configured to generate audit records containing information to establish where the events occurred, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA as shown in the example below.

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43140r666082_chk'
  tag severity: 'medium'
  tag gid: 'V-239907'
  tag rid: 'SV-239907r666084_rule'
  tag stig_id: 'CASA-ND-000280'
  tag gtitle: 'SRG-APP-000097-NDM-000227'
  tag fix_id: 'F-43099r666083_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
