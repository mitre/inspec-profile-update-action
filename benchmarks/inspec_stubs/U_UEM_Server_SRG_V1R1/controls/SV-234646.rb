control 'SV-234646' do
  title 'The UEM server must generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter). 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Verify the UEM server generates audit records when successful/unsuccessful attempts to modify security objects occur.

If the UEM server does not generate audit records when successful/unsuccessful attempts to modify security objects occur, this is a finding.'
  desc 'fix', 'Configure the UEM server to generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37831r616013_chk'
  tag severity: 'medium'
  tag gid: 'V-234646'
  tag rid: 'SV-234646r617355_rule'
  tag stig_id: 'SRG-APP-000496-UEM-000371'
  tag gtitle: 'SRG-APP-000496'
  tag fix_id: 'F-37796r615573_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
