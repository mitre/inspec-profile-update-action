control 'SV-234367' do
  title 'The UEM server must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password. 

Satisfies:FMT_SMF.1(2)b 
Reference:PP-MDM-431018'
  desc 'check', 'Verify the UEM server enforces a minimum 15-character password length.

If the UEM server does not enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the UEM server to enforce a minimum 15-character password length.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37552r614111_chk'
  tag severity: 'medium'
  tag gid: 'V-234367'
  tag rid: 'SV-234367r879601_rule'
  tag stig_id: 'SRG-APP-000164-UEM-000094'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-37517r614112_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
