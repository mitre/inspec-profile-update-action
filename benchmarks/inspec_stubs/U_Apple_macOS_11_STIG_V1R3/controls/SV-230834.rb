control 'SV-230834' do
  title 'The macOS system must enforce a minimum 15-character password length.'
  desc 'The minimum password length must be set to 15 characters. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'To check the currently applied policies for passwords and accounts, use the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minLength

If the return is null or not “minLength = 15”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33779r607389_chk'
  tag severity: 'medium'
  tag gid: 'V-230834'
  tag rid: 'SV-230834r599842_rule'
  tag stig_id: 'APPL-11-003010'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-33752r607390_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
