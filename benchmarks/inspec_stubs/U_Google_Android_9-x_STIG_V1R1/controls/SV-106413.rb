control 'SV-106413' do
  title 'The Google Android Pie must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of inactivity.

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console, do the following:
1. Open password requirements
2. Open device password section
3. Ensure "Device Lock Timeout" is set to any number desired. Units are in Minutes.

On the Android Pie device, do the following:
1. Open settings >> Security & location 
2. Click the "gear" icon next to "Screen lock"
3. Ensure "Automatically lock" is set at a required time

If the MDM console device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity or on the Android Pie device, the device policy is not set to enable a screen-lock policy that will lock the display after a period of inactivity, this is a finding.'
  desc 'fix', 'Configure the Google Android device to enable a screen-lock policy that will lock the display after a period of inactivity.

On the MDM Console:
1. Open password requirements.
2. Open device password section.
3. Set "Device Lock Timeout" to any number desired. Units are in Minutes.'
  impact 0.5
  ref 'DPMS Target Google Android 9.x'
  tag check_id: 'C-96145r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97309'
  tag rid: 'SV-106413r1_rule'
  tag stig_id: 'GOOG-09-000300'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-102989r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
