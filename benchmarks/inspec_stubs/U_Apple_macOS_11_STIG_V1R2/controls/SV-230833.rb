control 'SV-230833' do
  title 'The macOS system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'To check the currently applied policies for passwords and accounts, use the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep pinHistory

If the return is not “pinHistory = 5” or greater, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33778r607386_chk'
  tag severity: 'medium'
  tag gid: 'V-230833'
  tag rid: 'SV-230833r599842_rule'
  tag stig_id: 'APPL-11-003009'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-33751r607387_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
