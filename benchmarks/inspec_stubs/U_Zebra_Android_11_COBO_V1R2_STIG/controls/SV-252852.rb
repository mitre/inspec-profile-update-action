control 'SV-252852' do
  title 'Zebra Android 11 must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review Zebra Android device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of inactivity.

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM Console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Max time to screen lock" is set to any number desired. The units are in seconds.

On the Android 11 device, do the following:
1. Open Settings >> Display.
2. Tap "Screen timeout".
3. Ensure the Screen timeout value is set to the desired value and cannot be set to a larger value.

If the EMM console device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity or on the Android 11 device, the device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 11 device to enable a screen-lock policy that will lock the display after a period of inactivity.

On the EMM Console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Set "Max time to screen lock" to any number desired. The units are in seconds.'
  impact 0.5
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56308r820481_chk'
  tag severity: 'medium'
  tag gid: 'V-252852'
  tag rid: 'SV-252852r820483_rule'
  tag stig_id: 'ZEBR-11-000300'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-56258r820482_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
