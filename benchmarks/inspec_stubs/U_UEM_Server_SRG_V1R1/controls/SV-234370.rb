control 'SV-234370' do
  title 'The UEM server must enforce password complexity by requiring that at least one lowercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 

Satisfies:FMT_SMF.1(2)b 
Reference:PP-MDM-431019'
  desc 'check', 'Verify the UEM server enforces password complexity by requiring that at least one lowercase character be used.

If the UEM server does not enforce password complexity by requiring that at least one lowercase character be used, this is a finding.'
  desc 'fix', 'Configure the UEM server to enforce password complexity by requiring that at least one lowercase character be used.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37555r614120_chk'
  tag severity: 'medium'
  tag gid: 'V-234370'
  tag rid: 'SV-234370r617355_rule'
  tag stig_id: 'SRG-APP-000167-UEM-000097'
  tag gtitle: 'SRG-APP-000167'
  tag fix_id: 'F-37520r614121_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
