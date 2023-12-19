control 'SV-237002' do
  title 'Google Android 10 must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of inactivity.

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console, do the following:
1. Open password requirements.
2. Open device password section.
3. Ensure "Max time to screen lock" is set to any number desired. Units are in Seconds.

On the Android 10 device, do the following:
1. Open Settings >> Display.
2. Tap "Screen timeout".
3. Ensure the Screen timeout value is set to the desired value and cannot be set to a larger value.

If the MDM console device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity or on the Android 10 device, the device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity, this is a finding.'
  desc 'fix', 'Configure the Google Android device to enable a screen-lock policy that will lock the display after a period of inactivity.

On the MDM Console:
1. Open password requirements.
2. Open device password section.
3. Set "Max time to screen lock" to any number desired. Units are in Seconds.'
  impact 0.5
  ref 'DPMS Target Google Android 10-x'
  tag check_id: 'C-40221r639150_chk'
  tag severity: 'medium'
  tag gid: 'V-237002'
  tag rid: 'SV-237002r639152_rule'
  tag stig_id: 'GOOG-10-000300'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-40184r639151_fix'
  tag 'documentable'
  tag legacy: ['SV-108029', 'V-98925']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
