control 'SV-258412' do
  title 'Google Android 14 must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2b'
  desc 'check', 'Review managed Google Android device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of 15 minutes or less of inactivity.

Note: Google Android 14 Settings User Interface (UI) does not support the 15-minute increment, but this value can be set by the MDM.

This validation procedure is performed on both the EMM Administration Console and the Android 14 device. 

On the EMM console:

COBO:

1. Open "Lock screen restrictions".
2. Verify that "Max time to screen lock" is set to "900".
Note: The units are in seconds.

COPE:

1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Max time to screen lock" is set to "900".
Note: The units are in seconds.

If the EMM console device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity of 900 seconds, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to enable a screen-lock policy of 15 minutes for the max period of inactivity. 

Note: Google Android 14 Settings User Interface (UI) does not support the 15-minute increment, but this value can be set by the MDM. 

On the EMM console:

COBO:

1. Open "Lock screen restrictions".
2. Set "Max time to screen lock" to "900".
Note: The units are in seconds.

COPE:

1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Set "Max time to screen lock" to 900".
Note: The units are in seconds.'
  impact 0.5
  ref 'DPMS Target Google Android 14 COPE'
  tag check_id: 'C-62153r928259_chk'
  tag severity: 'medium'
  tag gid: 'V-258412'
  tag rid: 'SV-258412r928261_rule'
  tag stig_id: 'GOOG-14-006300'
  tag gtitle: 'PP-MDF-333030'
  tag fix_id: 'F-62077r928260_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
