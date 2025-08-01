control 'SV-225208' do
  title 'The macOS system must enforce a minimum 15-character password length.'
  desc 'The minimum password length must be set to 15 characters. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'To check the currently applied policies for passwords and accounts, use the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minLength

If the return is null or not “minLength = 15”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Passcode Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26907r467792_chk'
  tag severity: 'medium'
  tag gid: 'V-225208'
  tag rid: 'SV-225208r610901_rule'
  tag stig_id: 'AOSX-15-003010'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-26895r467793_fix'
  tag 'documentable'
  tag legacy: ['V-102835', 'SV-111797']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
