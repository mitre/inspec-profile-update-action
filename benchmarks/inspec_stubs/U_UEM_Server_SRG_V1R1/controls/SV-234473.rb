control 'SV-234473' do
  title 'The UEM server must employ an audited override of automated access control mechanisms under organization-defined conditions.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. Actions that could adversely impact the system must be audited for forensic analysis. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Verify the UEM server employs an audited override of automated access control mechanisms under organization-defined conditions.

If the UEM server does not employ an audited override of automated access control mechanisms under organization-defined conditions, this is a finding.'
  desc 'fix', 'Configure the UEM server to employ an audited override of automated access control mechanisms under organization-defined conditions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37658r614429_chk'
  tag severity: 'medium'
  tag gid: 'V-234473'
  tag rid: 'SV-234473r617355_rule'
  tag stig_id: 'SRG-APP-000327-UEM-000200'
  tag gtitle: 'SRG-APP-000327'
  tag fix_id: 'F-37623r614430_fix'
  tag 'documentable'
  tag cci: ['CCI-002186']
  tag nist: ['AC-3 (10)']
end
