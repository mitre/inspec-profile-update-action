control 'SV-230079' do
  title 'The Motorola Android Pie must be configured to enable a screen lock policy that will lock the display after a period of inactivity.'
  desc 'The screen lock timeout helps protect the device from unauthorized access. Devices without a screen lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review Motorola Android device configuration settings to determine if the mobile device is enforcing a screen lock policy that will lock the display after a period of inactivity.

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console: 
1. Open password requirements.
2. Open device password section.
3. Verify "Device Lock Timeout" is set to any number desired. Units are in minutes.

On the Android Pie device: 
1. Open Settings >> Security & location.
2. Click the gear icon next to "Screen lock".
3. Verify "Automatically lock" is set to a required time.

If the MDM console device policy is not set to enable a screen lock policy that will lock the display after a period of inactivity, or on the Android Pie device, the device policy is not set to enable a screen lock policy that will lock the display after a period of inactivity, this is a finding.'
  desc 'fix', 'Configure the Motorola Android device to enable a screen lock policy that will lock the display after a period of inactivity.

On the MDM console: 
1. Open password requirements.
2. Open device password section.
3. Set "Device Lock Timeout" to any number desired. Units are in minutes.'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-58153r859808_chk'
  tag severity: 'medium'
  tag gid: 'V-230079'
  tag rid: 'SV-230079r859810_rule'
  tag stig_id: 'MOTO-09-000300'
  tag gtitle: 'GOOG-09-000300'
  tag fix_id: 'F-58102r859809_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
