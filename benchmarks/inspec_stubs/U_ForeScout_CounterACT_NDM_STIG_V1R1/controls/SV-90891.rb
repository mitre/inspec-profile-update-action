control 'SV-90891' do
  title 'CounterACT must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Determine if the network device enforces a minimum 15-character password length. This requirement may be verified by demonstration or configuration review.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the "minimum length" is configured for "15".

If CounterACT does not enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', '1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Configure the "minimum length" for "15".
4. Verify additional complexity requirements are also met.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75889r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76203'
  tag rid: 'SV-90891r1_rule'
  tag stig_id: 'CACT-NM-000030'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-82841r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
