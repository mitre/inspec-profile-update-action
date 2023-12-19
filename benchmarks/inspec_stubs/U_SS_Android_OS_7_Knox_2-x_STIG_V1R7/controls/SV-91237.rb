control 'SV-91237' do
  title 'The Samsung Android 7 with Knox must be configured to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (HandsFree Profile), and SPP (Serial Port Profile).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore should be disabled.

SFR ID: FMT_SMF_EXT.1.1 #18h'
  desc 'check', 'Review documentation on the Samsung Android 7 with Knox and inspect the configuration on the Samsung Android 7 with Knox to disable all Bluetooth profiles except for HSP, HFP, and SPP. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allowed Bluetooth Profiles" settings in the "Android Bluetooth" rule. 
2. Verify the only profiles selected are HSP, HFP, and SPP.

On the Samsung Android 7 with Knox device, do the following:
1. Attempt to pair a Bluetooth peripheral that uses profiles other than HSP, HFP, and SPP (e.g., a Bluetooth keyboard).
2. Verify the Bluetooth peripheral does not pair with the Samsung Android 7 with Knox device.

If the MDM console "Allowed Bluetooth Profiles" is set to profiles other than HSP, HFP, and SPP or on the Samsung Android 7 with Knox device, is able to pair with a non HSP, HFP, and SPP profile (e.g., a Bluetooth keyboard), this is a finding.

Note: Disabling the Bluetooth radio will satisfy this requirement.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable all Bluetooth profiles except for HSP, HFP, and SPP.

On the MDM console, make sure that all options are deselected except HFP, HSP, and SPP in the "Allowed Bluetooth Profiles" setting in the "Android Bluetooth" rule.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76201r1_chk'
  tag severity: 'low'
  tag gid: 'V-76541'
  tag rid: 'SV-91237r1_rule'
  tag stig_id: 'KNOX-07-002400'
  tag gtitle: 'PP-MDF-301110'
  tag fix_id: 'F-83223r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
