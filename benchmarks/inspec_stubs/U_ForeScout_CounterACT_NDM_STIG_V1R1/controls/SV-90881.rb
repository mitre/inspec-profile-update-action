control 'SV-90881' do
  title 'For the local account, CounterACT must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced.

Nonlocal account are configured on the authentication server.'
  desc 'check', 'Determine if CounterACT is configured either to enforce the limit of three consecutive invalid logon attempts by a user during a "15" minute time period or to use an authentication server that would perform this function.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the "Lock account after" radio button is selected.
4. Verify that "3" password failures for "15" minutes is configured.

If the limit of three consecutive invalid logon attempts by a user during a "15" minute time period is not enforced, this is a finding.'
  desc 'fix', 'Configure CounterACT or its associated authentication server to enforce the limit of three consecutive invalid logon attempts by a user during a "15" minute time period.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Ensure the "Lock account after" radio button is selected.
4. Ensure that "3" password failures for "15" minutes is configured.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76193'
  tag rid: 'SV-90881r1_rule'
  tag stig_id: 'CACT-NM-000020'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-82831r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
