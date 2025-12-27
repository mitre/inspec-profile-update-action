control 'SV-209618' do
  title 'The macOS system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'To check the currently applied policies for passwords and accounts, use the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep pinHistory

If the return is not “pinHistory = 5” or greater, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9869r282336_chk'
  tag severity: 'medium'
  tag gid: 'V-209618'
  tag rid: 'SV-209618r610285_rule'
  tag stig_id: 'AOSX-14-003009'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-9869r282337_fix'
  tag 'documentable'
  tag legacy: ['V-95967', 'SV-105105']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
