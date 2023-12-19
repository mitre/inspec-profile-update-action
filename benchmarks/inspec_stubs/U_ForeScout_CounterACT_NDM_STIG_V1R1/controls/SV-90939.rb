control 'SV-90939' do
  title 'CounterACT must automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Determine CounterACT automatically locks the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.

This requirement may be verified by demonstration or configuration review.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the "Lock account After" radio button is selected.
4. Verify "3" is selected for the password failures setting.
5. Verify that "15" and "minutes" are selected.

If an account is not automatically locked out until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded, this is a finding.'
  desc 'fix', 'Configure CounterACT to automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Ensure the "Lock account After" radio button is selected.
4. Ensure that "3" is selected for the password failures setting.
5. Ensure that "15" and "minutes" are selected.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76251'
  tag rid: 'SV-90939r1_rule'
  tag stig_id: 'CACT-NM-000035'
  tag gtitle: 'SRG-APP-000345-NDM-000290'
  tag fix_id: 'F-82887r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
