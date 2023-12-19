control 'SV-90951' do
  title 'If multifactor authentication is not supported and passwords must be used, CounterACT must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Determine if CounterACT requires at least one upper-case character to be used in passwords. This requirement may be verified by demonstration or configuration review.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the "password must contain at least # upper case alphabetic characters" radio button is selected and configured to at least 1.

If CounterACT does not enforce at least one upper-case character, this is a finding.'
  desc 'fix', 'Configure CounterACT to require a minimum of one upper-case character.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Ensure the "password must contain at least # upper case alphabetic characters" radio button is selected and configured to at least 1.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75949r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76263'
  tag rid: 'SV-90951r1_rule'
  tag stig_id: 'CACT-NM-000147'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-82899r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
