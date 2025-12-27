control 'SV-234656' do
  title 'The UEM server must generate audit records when concurrent logons from different workstations occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter). 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Verify the UEM server generates audit records when concurrent logons from different workstations occur.

If the UEM server does not generate audit records when concurrent logons from different workstations occur, this is a finding.'
  desc 'fix', 'Configure the UEM server to generate audit records when concurrent logons from different workstations occur.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37841r615602_chk'
  tag severity: 'medium'
  tag gid: 'V-234656'
  tag rid: 'SV-234656r617355_rule'
  tag stig_id: 'SRG-APP-000506-UEM-000381'
  tag gtitle: 'SRG-APP-000506'
  tag fix_id: 'F-37806r615603_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
