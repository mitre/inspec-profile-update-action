control 'SV-258477' do
  title 'Google Android 13 must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DOD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review managed Google Android 13 device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of inactivity.

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 13 device. 

On the EMM console:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Verify that "Max time to screen lock" is set to any number desired, the units are in seconds.

On the managed Google Android 13 device:

1. Open Settings >> Display.
2. Tap "Screen timeout".
3. Ensure the Screen timeout value is set to the desired value and cannot be set to a larger value.

If the EMM console device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to enable a screen-lock policy that will lock the display after a period of inactivity.

On the EMM console:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Set "Max time to screen lock" to any number desired.
Note: The units are in seconds.'
  impact 0.5
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62217r929245_chk'
  tag severity: 'medium'
  tag gid: 'V-258477'
  tag rid: 'SV-258477r929247_rule'
  tag stig_id: 'GOOG-13-706200'
  tag gtitle: 'PP-MDF-333026'
  tag fix_id: 'F-62126r929246_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
