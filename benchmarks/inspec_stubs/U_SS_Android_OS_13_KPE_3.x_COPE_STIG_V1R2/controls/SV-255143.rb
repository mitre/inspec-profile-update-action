control 'SV-255143' do
  title 'Samsung Android must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2b'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are locking the device display after 15 minutes (or less) of inactivity.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device password policies, verify "max time to screen lock" is set to "15 minutes" or less.

On the Samsung Android device:
1. Open Settings >> Lock screen.
2. Verify "Secure lock settings" is present and tap it.
3. Enter current password.
4. Tap "Auto lock when screen turns off".
5. Verify the listed timeout values are 15 minutes or less.

If on the management tool "max time to screen lock" is not set to "15 minutes" or less, or on the Samsung Android device "Secure lock settings" is not present and the listed Screen timeout values include durations of more than 15 minutes, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to lock the device display after 15 minutes (or less) of inactivity.

On the management tool, in the device password policies, set "max time to screen lock" to "15 minutes" or less.

A device password must be set for "max time to screen lock" to become active.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58756r867364_chk'
  tag severity: 'medium'
  tag gid: 'V-255143'
  tag rid: 'SV-255143r867366_rule'
  tag stig_id: 'KNOX-13-210070'
  tag gtitle: 'PP-MDF-323030'
  tag fix_id: 'F-58700r867365_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
