control 'SV-90657' do
  title 'The OS X system must be configured with Infrared [IR] support disabled.'
  desc 'IR kernel support must be disabled to prevent users from controlling the system with IR devices. By default, if IR is enabled, the system will accept IR control from any remote device.'
  desc 'check', 'To check if IR support is disabled, run the following command:

/usr/bin/sudo /usr/bin/defaults read /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled

If the result is not "0", this is a finding.'
  desc 'fix', 'To disable IR, run the following command:

/usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled -bool FALSE'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75653r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75969'
  tag rid: 'SV-90657r1_rule'
  tag stig_id: 'AOSX-12-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82607r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
