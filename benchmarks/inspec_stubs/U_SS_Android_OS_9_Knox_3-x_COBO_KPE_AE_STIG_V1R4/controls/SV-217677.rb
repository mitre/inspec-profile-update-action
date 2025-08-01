control 'SV-217677' do
  title 'Samsung Android must be configured to disable all Bluetooth profiles except HSP (Headset Profile), HFP (HandsFree Profile), SPP (Serial Port Profile), A2DP (Advanced Audio Distribution Profile), AVRCP (Audio/Video Remote Control Profile), and PBAP (Phone Book Access Profile).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore should be disabled.

SFR ID: FMT_SMF_EXT.1.1 #18h'
  desc 'check', 'Review device configuration settings to confirm that all Bluetooth profiles are disabled except HSP, HFP, and SPP, A2DP, AVRCP, and PBAP. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox Bluetooth" group, verify that only "HFP, HSP, SPP, A2DP, AVRCP, and PBAP" are selected in the "allowed profiles". 

On the Samsung Android device, verify that a Bluetooth peripheral that uses a profile other than HSP, HFP, SPP, A2DP, AVRCP, or PBAP (e.g., a Bluetooth keyboard) cannot be paired. 

If on the MDM console "allowed profiles" has any selection other than "HSP, HFP, SPP, A2DP, AVRCP, and PBAP", or the Samsung Android device is able to pair with a Bluetooth keyboard, this is a finding. 

Note: Disabling the Bluetooth radio will satisfy this requirement.'
  desc 'fix', 'Configure Samsung Android to disable all Bluetooth profiles except HSP, HFP, SPP, A2DP, AVRCP, and PBAP. 

On the MDM console, for the device, in the "Knox Bluetooth" group, select "HFP, HSP, SPP, A2DP, AVRCP, and PBAP" in the "allowed profiles".'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18896r362060_chk'
  tag severity: 'low'
  tag gid: 'V-217677'
  tag rid: 'SV-217677r388482_rule'
  tag stig_id: 'KNOX-09-000660'
  tag gtitle: 'PP-MDF-301110'
  tag fix_id: 'F-18894r362061_fix'
  tag 'documentable'
  tag legacy: ['SV-102979', 'V-92891']
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
