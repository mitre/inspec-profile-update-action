control 'SV-214893' do
  title 'The macOS system must be configured to not allow iTunes file sharing.'
  desc 'Connections to unauthorized iOS devices (e.g., iPhones, iPods, and iPads) open the system to possible compromise via exfiltration of system data. Disabling the iTunes file sharing blocks connections to iOS devices.'
  desc 'check', 'If iTunes file sharing is enabled, unauthorized disclosure could occur.

To verify that iTunes file sharing is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowiTunesFileSharing

If the result is null or is not “allowiTunesFileSharing = 0”, this is a finding'
  desc 'fix', 'This setting is enforced using the “Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16093r397251_chk'
  tag severity: 'medium'
  tag gid: 'V-214893'
  tag rid: 'SV-214893r609363_rule'
  tag stig_id: 'AOSX-13-000862'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16091r397252_fix'
  tag 'documentable'
  tag legacy: ['SV-96379', 'V-81665']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
