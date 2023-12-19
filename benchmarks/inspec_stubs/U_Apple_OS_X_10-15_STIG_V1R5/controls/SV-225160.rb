control 'SV-225160' do
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
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26859r467648_chk'
  tag severity: 'medium'
  tag gid: 'V-225160'
  tag rid: 'SV-225160r610901_rule'
  tag stig_id: 'AOSX-15-002002'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26847r467649_fix'
  tag 'documentable'
  tag legacy: ['V-102739', 'SV-111701']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
