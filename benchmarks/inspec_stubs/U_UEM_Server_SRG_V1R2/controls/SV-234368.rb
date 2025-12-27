control 'SV-234368' do
  title 'The UEM server must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements. 

Satisfies:FMT_SMF.1(2)b 
Reference:PP-MDM-431025'
  desc 'check', 'Verify the UEM server prohibits password reuse for a minimum of five generations.

If the UEM server does not prohibit password reuse for a minimum of five generations, this is a finding.'
  desc 'fix', 'Configure the UEM server to prohibit password reuse for a minimum of five generations.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37553r614114_chk'
  tag severity: 'medium'
  tag gid: 'V-234368'
  tag rid: 'SV-234368r879602_rule'
  tag stig_id: 'SRG-APP-000165-UEM-000095'
  tag gtitle: 'SRG-APP-000165'
  tag fix_id: 'F-37518r614115_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
