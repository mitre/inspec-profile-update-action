control 'SV-258411' do
  title 'Google Android 14 must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DOD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review managed Google Android 14 device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of inactivity.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 14 device. 

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Verify that "Max time to screen lock" is set to any number desired. 
Note: The units are in seconds.

COPE:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Select "Personal Profile".
4. Verify that "Max time to screen lock" is set to any number desired. 
Note: The units are in seconds.
___________________________

On the managed Google Android 14 device:

COBO and COPE:

1. Open Settings >> Display.
2. Tap "Screen timeout".
3. Ensure the Screen timeout value is set to the desired value and cannot be set to a larger value.

If the EMM console device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity or on the managed Google Android 14 device, the device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to enable a screen-lock policy that will lock the display after a period of inactivity.

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Set "Max time to screen lock" to any number desired.
Note: The units are in seconds.

COPE:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Select "Personal Profile".
4. Set "Max time to screen lock" to any number desired.
Note: The units are in seconds.'
  impact 0.5
  ref 'DPMS Target Google Android 14 COPE'
  tag check_id: 'C-62152r928256_chk'
  tag severity: 'medium'
  tag gid: 'V-258411'
  tag rid: 'SV-258411r928258_rule'
  tag stig_id: 'GOOG-14-006200'
  tag gtitle: 'PP-MDF-333026'
  tag fix_id: 'F-62076r928257_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
