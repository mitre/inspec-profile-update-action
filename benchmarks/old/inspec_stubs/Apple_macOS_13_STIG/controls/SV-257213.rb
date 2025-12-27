control 'SV-257213' do
  title 'The macOS system must disable the Screen Sharing feature.'
  desc 'The Screen Sharing feature allows remote users to view or control the desktop of the current user. A malicious user can take advantage of screen sharing to gain full access to the system remotely, either with stolen credentials or by guessing the username and password. Disabling Screen Sharing mitigates this risk.'
  desc 'check', 'Verify the macOS system is configured to disable the Screen Sharing feature with the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.screensharing

"com.apple.screensharing => disabled"

If "com.apple.screensharing" is not set to "disabled", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable the Screen Sharing service with the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.screensharing

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60898r905270_chk'
  tag severity: 'medium'
  tag gid: 'V-257213'
  tag rid: 'SV-257213r905272_rule'
  tag stig_id: 'APPL-13-002050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60839r905271_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
