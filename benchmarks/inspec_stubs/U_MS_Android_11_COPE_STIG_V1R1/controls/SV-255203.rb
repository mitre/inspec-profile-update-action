control 'SV-255203' do
  title 'Microsoft Android 11 must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DOD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of inactivity.

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Max time to screen lock" is set to any number desired. Units are in seconds.

On the Microsoft Android 11 device:
1. Open Settings >> Display.
2. Tap "Screen timeout".
3. Ensure the Screen timeout value is set to the desired value and cannot be set to a larger value.

If on the EMM console, the device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity, this is a finding.

If on the Android 11 device, the device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to enable a screen-lock policy that will lock the display after a period of inactivity.

On the EMM console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Set "Max time to screen lock" to any number desired. Units are in seconds.'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58816r877008_chk'
  tag severity: 'medium'
  tag gid: 'V-255203'
  tag rid: 'SV-255203r877009_rule'
  tag stig_id: 'MSFT-11-000300'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-58760r870714_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
