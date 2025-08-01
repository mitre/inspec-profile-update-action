control 'SV-234653' do
  title 'The UEM server must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter). 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Verify the UEM server generates audit records when successful/unsuccessful logon attempts occur.

If the UEM server does not generate audit records when successful/unsuccessful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the UEM server to generate audit records when successful/unsuccessful logon attempts occur.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37838r615593_chk'
  tag severity: 'medium'
  tag gid: 'V-234653'
  tag rid: 'SV-234653r879874_rule'
  tag stig_id: 'SRG-APP-000503-UEM-000378'
  tag gtitle: 'SRG-APP-000503'
  tag fix_id: 'F-37803r615594_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
