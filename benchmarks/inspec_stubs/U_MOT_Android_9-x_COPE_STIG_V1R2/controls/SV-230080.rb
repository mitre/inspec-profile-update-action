control 'SV-230080' do
  title 'The Motorola Android Pie must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2b'
  desc 'check', 'Review Motorola Android device configuration settings to determine if the mobile device has the screen lock timeout set to 15 minutes or less.

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console: 
1. Open passcode requirements.
2. Open device passcode section.
3. Verify "Device Lock Timeout" is set to any number between 1 and 15.

On the Android Pie device: 
1. Open Settings >> Security & location.
2. Click the gear icon next to "Screen lock".
3. Verify "Automatically lock" is set to between 0 and 15 minutes.

If the MDM console device policy is not set to 15 minutes or less for the screen lock timeout, or on the Android Pie device, the device policy is not set to 15 minutes or less for the screen lock timeout, this is a finding.'
  desc 'fix', 'Configure the Motorola Android device to lock the device display after 15 minutes (or less) of inactivity.

On the MDM console: 
1. Open password requirements.
2. Open device password section.
3. Set "Device Lock Timeout" to any number between 1 and 15.'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-58154r859811_chk'
  tag severity: 'medium'
  tag gid: 'V-230080'
  tag rid: 'SV-230080r859813_rule'
  tag stig_id: 'MOTO-09-000400'
  tag gtitle: 'GOOG-09-000400'
  tag fix_id: 'F-58103r859812_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
