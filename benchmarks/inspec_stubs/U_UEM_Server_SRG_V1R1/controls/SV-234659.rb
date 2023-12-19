control 'SV-234659' do
  title 'The UEM server must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter). 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server generates audit records for all account creations, modifications, disabling, and termination events.

If the UEM server does not generate audit records for all account creations, modifications, disabling, and termination events, this is a finding.'
  desc 'fix', 'Configure the UEM server to generate audit records for all account creations, modifications, disabling, and termination events.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37844r616017_chk'
  tag severity: 'medium'
  tag gid: 'V-234659'
  tag rid: 'SV-234659r617355_rule'
  tag stig_id: 'SRG-APP-000509-UEM-000384'
  tag gtitle: 'SRG-APP-000509'
  tag fix_id: 'F-37809r615612_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
