control 'SV-230975' do
  title 'Samsung Android must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

'
  desc 'check', 'Review Samsung Android configuration settings to determine if the mobile device has the screen lock timeout set to 15 minutes or less.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool:
1. Open the device password policies.
2. Verify "minimum password quality" is set to "Numeric" (or better).
3. Verify the "max time to screen lock" is set to "15 minutes" or less.

On the Samsung Android device:
1. Open Settings >> Lock screen.
2. Verify "Secure lock settings" is present and tap it.
3. Enter current password.
4. Tap "Lock automatically".
5. Verify the listed timeout values are 15 minutes or less.

If on the management tool the "minimum password quality" is not set to "Numeric" (or better) and "max time to screen lock" is not set to "15 minutes" or less, or on the Samsung Android device "Secure lock settings" is not present and the listed Screen timeout values include durations of more than 15 minutes, this is a finding.'
  desc 'fix', 'Configure Samsung Android to lock the device display after 15 minutes (or less) of inactivity.

On the management tool:
1. Open the device password policies.
2. Set "minimum password quality" to "Numeric" (or better).
3. Set the "max time to screen lock" to "15 minutes" or less.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33905r592417_chk'
  tag severity: 'medium'
  tag gid: 'V-230975'
  tag rid: 'SV-230975r607691_rule'
  tag stig_id: 'KNOX-11-000500'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-33878r592418_fix'
  tag satisfies: ['PP-MDF-301030', 'PP-MDF-301040\n\nSFR ID: FMT_SMF_EXT.1.1 #2a', 'FMT_SMF_EXT.1.1 #2b']
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
