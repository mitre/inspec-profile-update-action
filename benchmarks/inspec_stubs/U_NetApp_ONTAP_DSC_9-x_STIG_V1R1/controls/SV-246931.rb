control 'SV-246931' do
  title 'ONTAP must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Use "security login role config show -role admin -instance" to see the settings for "Maximum Number of Failed Attempts" and “Delay after Each Failed Login Attempt".

If ONTAP is not configured to enforce a limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes, this is a finding.'
  desc 'fix', 'For the each role, configure "security login role config modify -role <name> -max-failed-login-attempts 3" and "security login role config modify -role admin -delay-after-failed-login 60".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50363r769123_chk'
  tag severity: 'medium'
  tag gid: 'V-246931'
  tag rid: 'SV-246931r769125_rule'
  tag stig_id: 'NAOT-AC-000010'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-50317r769124_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
