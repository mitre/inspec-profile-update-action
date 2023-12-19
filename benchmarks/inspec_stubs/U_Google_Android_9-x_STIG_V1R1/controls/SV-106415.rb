control 'SV-106415' do
  title 'The Google Android Pie must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2b'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device has the screen lock timeout set to 15 minutes or less.

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console, do the following:

1. Open passcode requirements
2. Open device passcode section
3. Ensure "Device Lock Timeout" to any number between 1 and 15

On the Android Pie device, do the following:
1. Open settings >> Security & location 
2. Click the "gear" icon next to "Screen lock"
3. Ensure "Automatically lock" is set to between 0 and 15 minutes

If the MDM console device policy is not set to 15 minutes or less for the screen lock timeout or on the Android Pie device, the device policy is not set to 15 minutes or less for the screen lock timeout, this is a finding.'
  desc 'fix', 'Configure the Google Android device to lock the device display after 15 minutes (or less) of inactivity.

On the MDM Console:
1. Open password requirements.
2. Open device password section.
3. Set "Device Lock Timeout" to any number between 1 and 15.'
  impact 0.5
  ref 'DPMS Target Google Android 9.x'
  tag check_id: 'C-96147r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97311'
  tag rid: 'SV-106415r1_rule'
  tag stig_id: 'GOOG-09-000400'
  tag gtitle: 'PP-MDF-301040'
  tag fix_id: 'F-102991r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
