control 'SV-251814' do
  title 'Samsung Android must be configured to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (Hands-Free Profile), SPP (Serial Port Profile), A2DP (Advanced Audio Distribution Profile), AVRCP (Audio/Video Remote Control Profile), and PBAP (Phone Book Access Profile).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore must be disabled.

SFR ID: FMT_SMF_EXT.1.1/BLUETOOTH BT-8'
  desc 'check', 'Review the Samsung documentation and inspect the configuration to verify the Samsung Android devices are paired only with devices which support HSP, HFP, SPP, A2DP, AVRCP, and PBAP Bluetooth profiles.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions section, verify "Bluetooth" is set to the AO-approved selection; "Allow" - if the AO has approved the use of Bluetooth - or "Disallow", if not.

On the Samsung Android device: 
1. Open Settings >> Connections >> Bluetooth
2. Verify that all listed paired Bluetooth devices use only authorized Bluetooth profiles.

If on the management tool "Bluetooth" is not set to the AO-approved value, or the Samsung Android device is paired with a device which uses unauthorized Bluetooth profiles, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable Bluetooth, or if the AO has approved the use of Bluetooth (for example, for hands-free use), train users to only pair devices which support HSP, HFP, SPP, A2DP, AVRCP, PBAP profiles.

On the management tool, in the device restrictions section, set "Bluetooth" to the AO-approved selection; "Allow" - if the AO has approved the use of Bluetooth - or "Disallow", if not.

The user training requirement is satisfied in requirement KNOX-12-110290.'
  impact 0.3
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55274r814196_chk'
  tag severity: 'low'
  tag gid: 'V-251814'
  tag rid: 'SV-251814r816517_rule'
  tag stig_id: 'KNOX-12-110120'
  tag gtitle: 'PP-MDF-323320'
  tag fix_id: 'F-55228r814197_fix'
  tag 'documentable'
  tag cci: ['CCI-001761', 'CCI-000366']
  tag nist: ['CM-7 (1) (b)', 'CM-6 b']
end
