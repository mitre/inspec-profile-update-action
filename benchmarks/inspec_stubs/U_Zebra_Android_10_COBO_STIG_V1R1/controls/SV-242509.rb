control 'SV-242509' do
  title 'Zebra Android 10 must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2b'
  desc 'check', 'Review Zebra Android 10 device configuration settings to determine if the mobile device has the screen lock timeout set to 15 minutes or less.

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console:
1. Open passcode requirement.
2. Open device passcode section.
3. Verify "Max time to screen lock" is set to any number between 1 and 15.

On the Zebra Android 10 device:
1. Open settings >> Security.
2. Tap on "Screen timeout".
3. Verify the Screen timeout value is set to between 0 and 15 minutes.

If the MDM console device policy is not set to 15 minutes or less for the screen lock timeout or on the Zebra Android 10 device, the device policy is not set to 15 minutes or less for the screen lock timeout, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to lock the device display after 15 minutes (or less) of inactivity.

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Set "Max time to screen lock" to any number between 1 and 15.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45784r714370_chk'
  tag severity: 'medium'
  tag gid: 'V-242509'
  tag rid: 'SV-242509r714372_rule'
  tag stig_id: 'ZEBR-10-000400'
  tag gtitle: 'PP-MDF-301040'
  tag fix_id: 'F-45741r714371_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
