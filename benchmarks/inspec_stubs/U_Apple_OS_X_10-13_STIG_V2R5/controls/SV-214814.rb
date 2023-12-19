control 'SV-214814' do
  title 'The macOS system must be configured with Infrared [IR] support disabled.'
  desc 'IR kernel support must be disabled to prevent users from controlling the system with IR devices. By default, if IR is enabled, the system will accept IR control from any remote device.'
  desc 'check', 'To check if IR support is disabled, run the following command:

/usr/bin/sudo /usr/bin/defaults read /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled

If the result is not "0", this is a finding.'
  desc 'fix', 'To disable IR, run the following command:

/usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled -bool FALSE'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16014r397014_chk'
  tag severity: 'medium'
  tag gid: 'V-214814'
  tag rid: 'SV-214814r609363_rule'
  tag stig_id: 'AOSX-13-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16012r397015_fix'
  tag 'documentable'
  tag legacy: ['SV-96201', 'V-81487']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
