control 'SV-96035' do
  title 'The Central Log Server must be configured to enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to enforce a minimum 15-character password length.

If the Central Log Server is not configured to enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to enforce a minimum 15-character password length.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-81023r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81321'
  tag rid: 'SV-96035r1_rule'
  tag stig_id: 'SRG-APP-000164-AU-002480'
  tag gtitle: 'SRG-APP-000164-AU-002480'
  tag fix_id: 'F-88105r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
