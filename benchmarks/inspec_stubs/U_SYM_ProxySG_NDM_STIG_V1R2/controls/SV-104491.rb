control 'SV-104491' do
  title 'Symantec ProxySG must be configured to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Verify the lockout policy is configured.

1. SSH into the ProxySG console, type "enable", press "Enter".
2. Enter the appropriate password, type "config", press "Enter". 
3. Type "show security local-user-list", press "Enter". 

This should return a value of "3" for the "Max failed attempts" and "900" for the value of both the "lockout duration" and "reset interval" fields.

If Symantec ProxySG is not configured to enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period, this is a finding.'
  desc 'fix', 'The lockout policy may be configured for both SSH and Web Management Console sessions. 

1. SSH into the ProxySG console, type "enable", press "Enter".
2. Enter the appropriate password, type "config", press "Enter". 
3. Type "security local-user-list edit local_user_database", press "Enter". 
4. Type "lockout-duration 900", type "max-failed-attempts 3", press "Enter".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93851r2_chk'
  tag severity: 'medium'
  tag gid: 'V-94661'
  tag rid: 'SV-104491r1_rule'
  tag stig_id: 'SYMP-NM-000050'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-100779r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
