control 'SV-90923' do
  title 'CounterACT must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify CounterACT enforces password complexity by requiring that at least one special character be used. This requirement may be verified by demonstration, configuration review, or validated test results.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the complexity requirement for use of at least one special character is met.

If CounterACT does not require that at least one special character be used in each password, this is a finding.'
  desc 'fix', '1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Configure the complexity requirement for use of at least one special character.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76235'
  tag rid: 'SV-90923r1_rule'
  tag stig_id: 'CACT-NM-000033'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-82871r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
