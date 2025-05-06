control 'SV-237767' do
  title 'The macOS system must enforce requirements for remote connections to the information'
  desc 'The Screen Sharing feature allows remote users to view or control the desktop of the current user. A malicious user can take advantage of screen sharing to gain full access to the system remotely, either with stolen credentials or by guessing the username and password. Disabling Screen Sharing mitigates this risk.'
  desc 'check', 'To check if the Screen Sharing service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.screensharing

If the results do not show the following, this is a finding:

"com.apple.screensharing" => true'
  desc 'fix', 'To disable the Screen Sharing service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.screensharing

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-40981r648732_chk'
  tag severity: 'medium'
  tag gid: 'V-237767'
  tag rid: 'SV-237767r648733_rule'
  tag stig_id: 'AOSX-13-000057'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33737r607345_fix'
  tag 'documentable'
  tag legacy: ['V-81481', 'SV-96195']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
