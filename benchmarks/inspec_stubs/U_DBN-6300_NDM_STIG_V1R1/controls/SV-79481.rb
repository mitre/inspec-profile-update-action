control 'SV-79481' do
  title 'The DBN-6300 must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.

It is possible to set a time-to-retry variable, as well as number of retries during that lockout timeout variable, within the DBN-6300.'
  desc 'check', 'To see if the system will lock out the user if three failed logon attempts occur within 15 minutes, attempt to log on as a user three times in succession and deliberately fail (by entering the wrong password).

After the third attempt, the user will be locked out from retrying until the oldest attempt (by time) ages out past the 15-minute mark and then will be allowed to try again.

If the user is not locked out after three failed logon attempts within 15 minutes, this is a finding.'
  desc 'fix', 'Set a time-to-retry variable, as well as number of retries during that lockout timeout variable, within the DBN-6300 through the CLI.

This value is set with the following registry entry in the CLI:

reg set /sysconfig/auth/01 {"stores": { "local": { "policies": { "passwordFail": { "enable": true, "threshold": 3, "windowSeconds": 60 }}}}}'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-65649r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64991'
  tag rid: 'SV-79481r1_rule'
  tag stig_id: 'DBNW-DM-000015'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-70931r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
