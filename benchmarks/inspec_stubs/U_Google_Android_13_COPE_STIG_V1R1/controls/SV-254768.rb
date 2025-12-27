control 'SV-254768' do
  title 'Google Android 13 must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2b'
  desc 'check', 'Review managed Google Android device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of 15 minutes or less of inactivity.

Note: Google Android 13 does not support the 15 minute increment. The available allowable selection is 10 mins then increases to 30 minutes. Therefore, the control should be set to 10 minutes.

This validation procedure is performed on both the EMM Administration Console and the Android 13 device. 

On the EMM Console:

COBO:

1. Open "Lock screen restrictions".
2. Verify that "Max time to screen lock" is set to "600".
Note: The units are in seconds.

COPE:

1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Max time to screen lock" is set to "600".
Note: The units are in seconds.

On the managed Google Android 13 device:

COBO and COPE:

1. Open Settings >> Display.
2. Tap "Screen timeout".
3. Ensure the Screen timeout value is set to "600" seconds.

If the EMM console device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity of 600 seconds, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to enable a screen-lock policy of 15 minutes for the max period of inactivity. 

Note: Google Android 13 does not support the 15 minute increment. The available allowable selection is 10 mins then increases to 30 minutes. Therefore, the control will be set to 10 minutes.

On the EMM Console:

COBO:

1. Open "Lock screen restrictions".
2. Set "Max time to screen lock" to "600".
Note: The units are in seconds.

COPE:

1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Set "Max time to screen lock" to "600".
Note: The units are in seconds.'
  impact 0.5
  ref 'DPMS Target Google Android 13 COPE'
  tag check_id: 'C-58379r862684_chk'
  tag severity: 'medium'
  tag gid: 'V-254768'
  tag rid: 'SV-254768r862686_rule'
  tag stig_id: 'GOOG-13-006300'
  tag gtitle: 'PP-MDF-323030'
  tag fix_id: 'F-58325r862685_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
