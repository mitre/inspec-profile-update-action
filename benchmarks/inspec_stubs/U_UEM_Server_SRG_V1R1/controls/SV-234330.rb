control 'SV-234330' do
  title 'The UEM server must be configured to produce audit records containing information to establish where the events occurred.'
  desc 'Failure to generate these audit records makes it more difficult to identify or investigate attempted or successful compromises, potentially causing incidents to last longer than necessary. 

Satisfies:FAU_GEN.1.2(1) 
Reference:PP-MDM-412060'
  desc 'check', 'Verify the UEM server produces audit records containing information to establish where the events occurred.

If the UEM server does not produce audit records containing information to establish where the events occurred, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to produce audit records containing information to establish where the events occurred.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37515r614000_chk'
  tag severity: 'medium'
  tag gid: 'V-234330'
  tag rid: 'SV-234330r617355_rule'
  tag stig_id: 'SRG-APP-000097-UEM-000057'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-37480r614001_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
