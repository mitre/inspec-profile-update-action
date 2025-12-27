control 'SV-209567' do
  title 'The macOS system must be configured to disable Apple File (AFP) Sharing.'
  desc 'File Sharing is non-essential and must be disabled. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', 'To check if the Apple File (AFP) Sharing service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.AppleFileServer

If the results do not show the following, this is a finding:

"com.apple.AppleFileServer" => true'
  desc 'fix', 'To disable the Apple File (AFP) Sharing service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.AppleFileServer

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9818r282183_chk'
  tag severity: 'medium'
  tag gid: 'V-209567'
  tag rid: 'SV-209567r610285_rule'
  tag stig_id: 'AOSX-14-002002'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-9818r282184_fix'
  tag 'documentable'
  tag legacy: ['SV-105005', 'V-95867']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
