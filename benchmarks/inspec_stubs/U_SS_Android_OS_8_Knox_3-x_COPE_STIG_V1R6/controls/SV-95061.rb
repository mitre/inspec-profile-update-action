control 'SV-95061' do
  title 'Samsung Android 8 with Knox must be configured to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (HandsFree Profile), SPP (Serial Port Profile), A2DP (Advanced Audio Distribution Profile), AVRCP (Audio/Video Remote Control Profile), and PBAP (Phone Book Access Profile).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore should be disabled.

SFR ID: FMT_SMF_EXT.1.1 #18h'
  desc 'check', 'Review documentation on Samsung Android 8 with Knox and inspect the configuration on Samsung Android 8 with Knox to disable all Bluetooth profiles except for HSP, HFP, SPP, A2DP, AVRCP, and PBAP. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allowed Bluetooth Profiles" settings in the "Android Bluetooth" rule. 
2. Verify the only profiles selected are HSP, HFP, SPP, A2DP, AVRCP, and PBAP.

On the Samsung Android 8 with Knox device, do the following:
1. Attempt to pair a Bluetooth peripheral that uses profiles other than HSP, HFP, SPP, A2DP, AVRCP, and PBAP (e.g., a Bluetooth keyboard).
2. Verify the Bluetooth peripheral does not pair with the Samsung Knox for Android device.

If the MDM console "Allowed Bluetooth Profiles" is set to profiles other than HSP, HFP, SPP, A2DP, AVRCP, or PBAP or the Samsung Android 8 with Knox device is able to pair with a Bluetooth keyboard, this is a finding.

Note: Disabling the Bluetooth radio will satisfy this requirement.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox to disable all Bluetooth profiles except for HSP, HFP, SPP, A2DP, AVRCP, and PBAP.

On the MDM console, ensure that all options are deselected except HFP, HSP, SPP, A2DP, AVRCP, and PBAP in the "Allowed Bluetooth Profiles" setting in the "Android Bluetooth" rule.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80029r2_chk'
  tag severity: 'low'
  tag gid: 'V-80357'
  tag rid: 'SV-95061r2_rule'
  tag stig_id: 'KNOX-08-013900'
  tag gtitle: 'PP-MDF-301110'
  tag fix_id: 'F-87163r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
