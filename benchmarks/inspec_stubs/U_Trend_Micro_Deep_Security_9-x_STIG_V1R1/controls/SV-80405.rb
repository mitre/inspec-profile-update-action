control 'SV-80405' do
  title 'Trend Deep Security must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure a minimum 15-character password length is enforced.

Verify the policy value for minimum password length.

If the value for “User password minimum length” under the Administration >> System Settings >> Security tab is not set to 15, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to enforce a minimum 15-character password length.

Configure the policy value for minimum password length.

Under the Administration >> System Settings >> Security tab, set the value for “User password minimum length” to 15.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66563r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65915'
  tag rid: 'SV-80405r1_rule'
  tag stig_id: 'TMDS-00-000140'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-71991r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
