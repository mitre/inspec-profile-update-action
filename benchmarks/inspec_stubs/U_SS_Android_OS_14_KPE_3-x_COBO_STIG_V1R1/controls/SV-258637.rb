control 'SV-258637' do
  title 'Samsung Android must be configured to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (Hands-Free Profile), SPP (Serial Port Profile), A2DP (Advanced Audio Distribution Profile), AVRCP (Audio/Video Remote Control Profile), and PBAP (Phone Book Access Profile).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DOD data without encryption or otherwise do not meet DOD IT security policies and therefore must be disabled.

SFR ID: FMT_SMF_EXT.1.1/BLUETOOTH BT-8'
  desc 'check', 'Review the Samsung documentation and inspect the configuration to verify the Samsung Android devices are paired only with devices that support HSP, HFP, SPP, A2DP, AVRCP, and PBAP Bluetooth profiles.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions section, verify "Bluetooth" is set to the AO-approved selection: "Allow" if the AO has approved the use of Bluetooth or "Disallow" if the AO has not approved its use.

On the Samsung Android device: 
1. Open Settings >> Connections >> Bluetooth.
2. Verify all listed paired Bluetooth devices use only authorized Bluetooth profiles.

If on the management tool "Bluetooth" is not set to the AO-approved value, or the Samsung Android device is paired with a device that uses unauthorized Bluetooth profiles, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable Bluetooth, or if the AO has approved the use of Bluetooth (for example, for hands-free use), train users to only pair devices that support HSP, HFP, SPP, A2DP, AVRCP, and PBAP profiles.

On the management tool, in the device restrictions section, set "Bluetooth" to the AO-approved selection: "Allow" if the AO has approved the use of Bluetooth or "Disallow" if the AO has not approved its use.

The user training requirement is satisfied in requirement KNOX-14-110300.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62377r931109_chk'
  tag severity: 'low'
  tag gid: 'V-258637'
  tag rid: 'SV-258637r931111_rule'
  tag stig_id: 'KNOX-14-110120'
  tag gtitle: 'PP-MDF-333320'
  tag fix_id: 'F-62286r931110_fix'
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001761']
  tag nist: ['CM-7 a', 'CM-7 (1) (b)']
end
