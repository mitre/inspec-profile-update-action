control 'SV-255246' do
  title 'SSMC must enforce the limit of three consecutive invalid logon attempts by a nonadministrative user.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Check if SSMC is configured to limit consecutive invalid logon attempts for ssmcaudit user to three times by executing the following command:

$ sudo /ssmc/bin/config_security.sh -o session_lock -a status
Session lock is enabled

If the output of this command does not read "Session lock is enabled", this is a finding.'
  desc 'fix', 'Configure SSMC to limit consecutive invalid logon attempts for ssmcaudit user to three times by executing the following command:

$sudo /ssmc/bin/config_security.sh -o session_lock -a enable -f'
  impact 0.3
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58859r869886_chk'
  tag severity: 'low'
  tag gid: 'V-255246'
  tag rid: 'SV-255246r869888_rule'
  tag stig_id: 'SSMC-OS-020000'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-58803r869887_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
