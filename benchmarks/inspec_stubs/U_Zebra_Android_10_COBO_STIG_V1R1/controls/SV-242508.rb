control 'SV-242508' do
  title 'Zebra Android 10 must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review Zebra Android 10 device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of inactivity.

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Verify "Max time to screen lock" is set to any number desired. Units are in seconds.

On the Zebra Android 10 device:
1. Open Settings >> Display.
2. Tap "Screen timeout".
3. Verify the Screen timeout value is set to the desired value and cannot be set to a larger value.

If the MDM console device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity or on the Zebra Android 10 device, the device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to enable a screen-lock policy that will lock the display after a period of inactivity.

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Set "Max time to screen lock" to any number desired. Units are in seconds.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45783r714367_chk'
  tag severity: 'medium'
  tag gid: 'V-242508'
  tag rid: 'SV-242508r714369_rule'
  tag stig_id: 'ZEBR-10-000300'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-45740r714368_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
