control 'SV-234654' do
  title 'The UEM server must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter). 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Verify the UEM server generates audit records for privileged activities or other system-level access.

If the UEM server does not generate audit records for privileged activities or other system-level access, this is a finding.'
  desc 'fix', 'Configure the UEM server to generate audit records for privileged activities or other system-level access.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37839r615596_chk'
  tag severity: 'medium'
  tag gid: 'V-234654'
  tag rid: 'SV-234654r879875_rule'
  tag stig_id: 'SRG-APP-000504-UEM-000379'
  tag gtitle: 'SRG-APP-000504'
  tag fix_id: 'F-37804r615597_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
