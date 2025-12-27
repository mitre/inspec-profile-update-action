control 'SV-239937' do
  title 'The Cisco ASA must be configured to generate audit records showing starting and ending time for administrator access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco ASA configuration to verify it is compliant with this requirement. The configuration should look similar to the example below.

logging enable
logging timestamp
logging buffered informational

Note: The ASA will log all login attempts as well as log the administrator’s name and time executing the enable command. The ASA will also log the time when the administrator logs out.

If the Cisco ASA is not configured to generate log records showing starting and ending time for administrator access to the system, this is a finding.'
  desc 'fix', 'Configure the ASA to log session start and ending per admin session as shown in the example below.

ASA(config)# logging enable
ASA(config)# logging timestamp
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43170r666172_chk'
  tag severity: 'medium'
  tag gid: 'V-239937'
  tag rid: 'SV-239937r666174_rule'
  tag stig_id: 'CASA-ND-001240'
  tag gtitle: 'SRG-APP-000505-NDM-000322'
  tag fix_id: 'F-43129r666173_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
