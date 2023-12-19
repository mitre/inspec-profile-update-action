control 'SV-231020' do
  title 'Samsung Android must be configured to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (HandsFree Profile), SPP (Serial Port Profile), A2DP (Advanced Audio Distribution Profile), AVRCP (Audio/Video Remote Control Profile), and PBAP (Phone Book Access Profile).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore should be disabled.

SFR ID: FMT_SMF_EXT.1.1 #18h'
  desc 'check', 'Review Samsung Android configuration settings to determine if all Bluetooth profiles are disabled except for HSP, HFP, SPP, A2DP, AVRCP, and PBAP.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device Bluetooth section, verify that only DoD-approved profile UUIDs are listed in the "Bluetooth UUID allowlist": HFP, HSP, SPP, A2DP, AVRCP, and PBAP.

On the Samsung Android device: 
1. Open Settings >> Connections >> Bluetooth.
2. Verify only Bluetooth devices that use DoD-approved profiles are listed.

If on the management tool the "Bluetooth UUID allowlist" contains non-DoD-approved profile UUIDs, or on the Samsung Android device Bluetooth devices that use non-DoD-approved profiles are listed, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable all Bluetooth profiles except for HSP, HFP, SPP, A2DP, AVRCP, and PBAP.

On the management tool, in the device Bluetooth section, add each DoD-approved profile UUID to the "Bluetooth UUID allowlist": HFP, HSP, SPP, A2DP, AVRCP, and PBAP.'
  impact 0.3
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33950r592674_chk'
  tag severity: 'low'
  tag gid: 'V-231020'
  tag rid: 'SV-231020r608683_rule'
  tag stig_id: 'KNOX-11-002400'
  tag gtitle: 'PP-MDF-301110'
  tag fix_id: 'F-33923r592675_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
