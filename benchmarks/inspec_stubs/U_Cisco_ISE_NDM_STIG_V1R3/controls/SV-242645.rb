control 'SV-242645' do
  title 'For accounts using password authentication, the Cisco ISE must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the min-password length is set to 15.

Show password policy

If the Cisco ISE password policy is not configured to require a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the password policy.

password-policy min-password-length 15'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45920r714243_chk'
  tag severity: 'medium'
  tag gid: 'V-242645'
  tag rid: 'SV-242645r714245_rule'
  tag stig_id: 'CSCO-NM-000400'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-45877r714244_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
