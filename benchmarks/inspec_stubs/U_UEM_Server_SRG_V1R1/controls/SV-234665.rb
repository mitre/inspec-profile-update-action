control 'SV-234665' do
  title 'The UEM server must, at a minimum, off-load audit logs of interconnected systems in real time and off-load standalone systems weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

Satisfies:FMT_SMF.1.1(2) c.8, FAU_STG_EXT.1.1(1) 
Reference:PP-MDM-411054'
  desc 'check', 'Verify the UEM server, at a minimum, off-loads audit logs of interconnected systems in real time and off-load standalone systems weekly.

If the UEM server does not off-load audit logs of interconnected systems in real time and off-load standalone systems weekly, this is a finding.'
  desc 'fix', 'Configure the UEM server to, at a minimum, off-load audit logs of interconnected systems in real time and off-load standalone systems weekly.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37850r616019_chk'
  tag severity: 'medium'
  tag gid: 'V-234665'
  tag rid: 'SV-234665r617355_rule'
  tag stig_id: 'SRG-APP-000515-UEM-000390'
  tag gtitle: 'SRG-APP-000515'
  tag fix_id: 'F-37815r615630_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
