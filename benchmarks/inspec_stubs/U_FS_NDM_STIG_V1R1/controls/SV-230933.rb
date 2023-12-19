control 'SV-230933' do
  title 'Forescout must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Determine if Forescout is configured either to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period, or to use an authentication server to perform this function.

1. Log on to the Forescout Administrator UI.
2. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
3. Verify the "Lock account after" radio button is selected.
4. Verify that "3" password failures for "15 minutes" is configured.

If the limit of three consecutive invalid logon attempts by a user during a 15-minute time period is not enforced, this is a finding.'
  desc 'fix', 'Configure Forescout or its associated authentication server to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

1. Log on to the Forescout Administrator UI.
2. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
3. Ensure the "Lock account after" radio button is selected.
4. Ensure that "3" password failures for "15" minutes is configured.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33863r603638_chk'
  tag severity: 'medium'
  tag gid: 'V-230933'
  tag rid: 'SV-230933r615886_rule'
  tag stig_id: 'FORE-NM-000040'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-33836r603639_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
