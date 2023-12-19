control 'SV-257228' do
  title 'The macOS system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify the macOS system is configured to prohibit password reuse for a minimum of five generations with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "pinHistory"

pinHistory = 5;

If "pinHistory" is not set to "5" or greater, this is a finding.'
  desc 'fix', 'Configure the macOS system to prohibit password reuse for five generations by installing the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60913r905315_chk'
  tag severity: 'medium'
  tag gid: 'V-257228'
  tag rid: 'SV-257228r905317_rule'
  tag stig_id: 'APPL-13-003009'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-60854r905316_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
