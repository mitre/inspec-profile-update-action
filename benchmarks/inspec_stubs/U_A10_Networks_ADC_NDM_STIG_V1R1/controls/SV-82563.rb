control 'SV-82563' do
  title 'The A10 Networks ADC must automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Attempt to log on to an administrator account three times. On each attempt, deliberately enter an incorrect password. Attempt to log on a fourth time with a correct password.

If the attempt succeeds, this is a finding.

This can also be verified using the following command to view the lockout status of all administrative accounts:
show admin detail

If the Lock Status is not Locked, this is a finding.'
  desc 'fix', 'Use the following command to enable admin lockout:
admin lockout enable

The following command locks the admin account after three failed logon attempts sets the A10 ADC to remember the last failed logon for 15 minutes.
admin lockout threshold 3
admin lockout reset-time 15

Use the following command to enable admin lockout:
admin lockout enable

The following command keeps a locked admin account locked until it is manually unlocked by an authorized admin:
admin lockout duration 0'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68073'
  tag rid: 'SV-82563r1_rule'
  tag stig_id: 'AADC-NM-000093'
  tag gtitle: 'SRG-APP-000345-NDM-000290'
  tag fix_id: 'F-74189r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
