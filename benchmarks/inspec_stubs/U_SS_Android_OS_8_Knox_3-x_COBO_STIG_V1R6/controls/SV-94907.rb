control 'SV-94907' do
  title 'Samsung Android 8 with Knox must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2a, 2b'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is configured to lock the screen after 15 minutes (or less) of inactivity. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Maximum Time to Lock" setting in the "Android Password Restrictions" rule. 
2. Verify the value of the setting is the organization-defined value minus the maximum screen timeout or less. In this case, with Android 8, the value of the setting must be 5 minutes or less.

On the Samsung Android 8 with Knox device, do the following:
1. Unlock the device. 
2. Refrain from performing any activity on the device for 15 minutes.
3. Verify the device requires the user to enter the device unlock password to access the device.

If the MDM console "Maximum Time to Lock" is not set to 5 minutes or less for the lock timeout or on the Samsung Android 8 with Knox device, if after 15 minutes of inactivity the user does not have to enter a password to unlock the device, this is a finding.

Note: This value defines the amount of time from when the screen turns off until the device locks. Since the maximum screen timeout a user can select on Android 8 is 10 minutes, a 5-minute or less lock time value fulfills this requirement.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to lock the device display after 15 minutes (or less) of inactivity.

On the MDM console, configure the "Maximum Time to Lock" option to 15 minutes in the "Android Password Restrictions" rule.

Note: On some devices the max time to lock is the sum of the display screen timeout setting and the secured lock time setting on the device. On MDM configuration, the device makes a choice for these settings so that the sum is 15 minutes or less.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80203'
  tag rid: 'SV-94907r1_rule'
  tag stig_id: 'KNOX-08-009100'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-87009r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
