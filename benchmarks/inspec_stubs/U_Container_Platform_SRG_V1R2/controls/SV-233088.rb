control 'SV-233088' do
  title 'The container platform must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Review the container platform configuration to determine if the container platform enforces a minimum 15-character password length. 

If the container platform does not enforce a 15-character password length, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce a minimum 15-character password length.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36024r600751_chk'
  tag severity: 'medium'
  tag gid: 'V-233088'
  tag rid: 'SV-233088r600753_rule'
  tag stig_id: 'SRG-APP-000164-CTR-000400'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-35992r600752_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
