control 'SV-209619' do
  title 'The macOS system must enforce a minimum 15-character password length.'
  desc 'The minimum password length must be set to 15 characters. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'To check the currently applied policies for passwords and accounts, use the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minLength

If the return is null or not “minLength = 15”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9870r282339_chk'
  tag severity: 'medium'
  tag gid: 'V-209619'
  tag rid: 'SV-209619r610285_rule'
  tag stig_id: 'AOSX-14-003010'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-9870r282340_fix'
  tag 'documentable'
  tag legacy: ['SV-105107', 'V-95969']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
