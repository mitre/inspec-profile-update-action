control 'SV-96555' do
  title 'Apple iOS must implement the management setting: enable USB Restricted Mode.'
  desc 'The USB lightning port on an iOS device can be used to access data on the device. The required settings is that this control ensures the iOS device password is entered before a previously trusted USB accessory can connect to the device.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm USB Restricted Mode is enabled. Note that this is a User based Enforcement (UBE) control, unless Supervised mode has been implemented on the iOS device.

This check procedure is performed on the Apple iOS device (non-Supervised) or on an Apple iOS management tool (Supervised).

If the device is not Supervised, on the Apple iOS device:
1. Open the Settings app.
2. Tap "Touch ID & Passcode" or "Face ID & Passcode".
3. Scroll down to the "USB Accessories" setting.
4. Verify the "USB Accessories" setting is off.

If the device is Supervised, in the Apple iOS management tool, verify "Allow USB Accessories while device is locked" is checked (enabled). Note: The label for this configuration setting varies between MDM products. Ensure the setting is configured to disable USB accessory connection unless the device passcode is entered.

If the "USB Accessories" setting on the iOS device is not off or "Allow USB Accessories while device is locked" is not checked on the iOS management tool, this is a finding.'
  desc 'fix', 'If the iOS device is not Supervised, the user must disable "USB Accessories" on their iOS device. If the iOS device is Supervised, check (enable) "Allow USB Accessories while device is locked" on the Apple iOS management tool. Note: The label for this configuration setting varies between MDM products. Ensure the setting is configured to disable USB accessory connection unless the device passcode is entered.'
  impact 0.5
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-81633r3_chk'
  tag severity: 'medium'
  tag gid: 'V-81841'
  tag rid: 'SV-96555r1_rule'
  tag stig_id: 'AIOS-12-012500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-88691r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366', 'CCI-000370']
  tag nist: ['AC-20 (2)', 'CM-6 b', 'CM-6 (1)']
end
