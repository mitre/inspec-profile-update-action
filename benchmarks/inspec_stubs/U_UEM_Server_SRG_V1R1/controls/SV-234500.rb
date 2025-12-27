control 'SV-234500' do
  title 'The UEM server must be configured to transfer UEM server logs to another server for storage, analysis, and reporting. Note: UEM server logs include logs of UEM events and logs transferred to the UEM server by UEM agents of managed devices.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

Note: UEM server logs include logs of UEM events and logs transferred to the UEM server by UEM agents of managed devices. 

Satisfies:FMT_SMF.1.1(2) c.8, FAU_STG_EXT.1.1(1) 
Reference:PP-MDM-411054'
  desc 'check', 'Verify the UEM server transfers UEM server logs to another server for storage, analysis, and reporting.

If the UEM server does not transfer UEM server logs to another server for storage, analysis, and reporting, this is a finding.

Note: UEM server logs include logs of UEM events and logs transferred to the UEM server by UEM agents of managed devices.'
  desc 'fix', 'Configure the UEM server to be configured to transfer UEM server logs to another server for storage, analysis, and reporting.

Note: UEM server logs include logs of UEM events and logs transferred to the UEM server by UEM agents of managed devices.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37685r615967_chk'
  tag severity: 'medium'
  tag gid: 'V-234500'
  tag rid: 'SV-234500r617411_rule'
  tag stig_id: 'SRG-APP-000358-UEM-000228'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-37650r615144_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
