control 'SV-250388' do
  title 'Google Android 12 must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review managed Google Android 12 device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of inactivity.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 12 device. 

On the EMM Console:

COBO

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Verify that "Max time to screen lock" is set to any number desired, the units are in seconds.

COPE:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Select "Personal Profile".
4. Verify that "Max time to screen lock" is set to any number desired, the units are in seconds.
___________________________

On the managed Google Android 12 device:

COBO and COPE:

1. Open Settings >> Display.
2. Tap "Screen timeout".
3. Ensure the Screen timeout value is set to the desired value and cannot be set to a larger value.

If the EMM console device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity or on the managed Google Android 12 device, the device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity, this is a finding.'
  desc 'fix', 'Configure the Google Android 12 device to enable a screen-lock policy that will lock the display after a period of inactivity.

On the EMM Console:

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
  ref 'DPMS Target Google Android 12 COBO'
  tag check_id: 'C-53823r802714_chk'
  tag severity: 'medium'
  tag gid: 'V-250388'
  tag rid: 'SV-250388r802716_rule'
  tag stig_id: 'GOOG-12-006200'
  tag gtitle: 'PP-MDF-323026'
  tag fix_id: 'F-53777r802715_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
