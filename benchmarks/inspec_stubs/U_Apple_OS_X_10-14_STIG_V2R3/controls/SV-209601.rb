control 'SV-209601' do
  title 'The macOS system must disable the Screen Sharing feature.'
  desc 'The Screen Sharing feature allows remote users to view or control the desktop of the current user. A malicious user can take advantage of screen sharing to gain full access to the system remotely, either with stolen credentials or by guessing the username and password. Disabling Screen Sharing mitigates this risk.'
  desc 'check', 'To check if the Screen Sharing service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.screensharing

If the results do not show the following, this is a finding:

"com.apple.screensharing" => true'
  desc 'fix', 'To disable the Screen Sharing service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.screensharing

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9852r282285_chk'
  tag severity: 'medium'
  tag gid: 'V-209601'
  tag rid: 'SV-209601r610285_rule'
  tag stig_id: 'AOSX-14-002050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-9852r282286_fix'
  tag 'documentable'
  tag legacy: ['V-95941', 'SV-105079']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
