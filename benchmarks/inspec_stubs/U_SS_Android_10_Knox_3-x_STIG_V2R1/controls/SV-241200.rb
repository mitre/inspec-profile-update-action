control 'SV-241200' do
  title 'Samsung Android must be configured to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (HandsFree Profile), SPP (Serial Port Profile), A2DP (Advanced Audio Distribution Profile), AVRCP (Audio/Video Remote Control Profile), and PBAP (Phone Book Access Profile).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore should be disabled.

SFR ID: FMT_SMF_EXT.1.1 #18h'
  desc 'check', 'Review Samsung Android configuration settings to determine if all Bluetooth profiles are disabled except for HSP, HFP, SPP, A2DP, AVRCP, and PBAP.

Confirm if Method #1, #2, or #3 is used at the Samsung device site and follow the appropriate procedure. Method #2 or #3 must be used if the management tool supports management of Bluetooth profiles.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

****

Method #1: AO decision: Allow Bluetooth and train users to connect only authorized Bluetooth devices.

On the management tool, in the device restrictions section, verify "Bluetooth" is set to "Allow".

On the Samsung Android device, do the following:
1. Open Settings >> Connections >> Bluetooth.
2. Verify only Bluetooth devices that use DoD-approved profiles are listed.

If on the management tool "Bluetooth" is not set to "Allow", or on the Samsung Android device Bluetooth devices that use non-DoD-approved profiles are listed, this is a finding.

****

Method #2: AO decision: Disallow use of Bluetooth.

On the management tool, in the device restrictions section, verify that "Bluetooth" is set to "Disallow".

On the Samsung Android device, do the following:
1. Open Settings >> Connections >> Bluetooth.
2. Verify that Bluetooth is "Off" and cannot be toggled to "On".

If on the management tool "Bluetooth" is not set to "Disallow", or on the Samsung Android device Bluetooth is not "Off" or can be toggled "On", this is a finding.

****

Method #3: Use KPE Bluetooth UUID Whitelisting to allow only DoD-approved profiles.

On the management tool, in the device KPE Bluetooth section, verify that only DoD-approved profile UUIDs are listed in the "Bluetooth UUID whitelist":
- HFP (HFP_AG_UUID, HFP_UUID)
- HSP (HSP_AG_UUID, HSP_UUID)
- SPP (SPP_UUID)
- A2DP (A2DP_ADVAUDIODIST_UUID, A2DP_AUDIOSINK_UUID, A2DP_AUDIOSOURCE_UUID)
- AVRCP (AVRCP_CONTROLLER_UUID, AVRCP_TARGET_UUID)
- PBAP (PBAP_PSE_UUID, PBAP_UUID)

On the Samsung Android device, do the following:
1. Open Settings >> Connections >> Bluetooth.
2. Verify only Bluetooth devices that use DoD-approved profiles are listed.

If on the management tool the "Bluetooth UUID whitelist" contains non-DoD-approved profile UUIDs, or on the Samsung Android device Bluetooth devices that use non-DoD-approved profiles are listed, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable all Bluetooth profiles except for HSP, HFP, SPP, A2DP, AVRCP, and PBAP.

Do one of the following (Method #2 or #3 must be used if the management tool supports management of Bluetooth profiles):
- Method #1: AO decision: Allow Bluetooth and train users to connect only authorized Bluetooth devices.
- Method #2: AO decision: Disallow use of Bluetooth.
- Method #3: Use KPE Bluetooth UUID Whitelisting to allow only DoD-approved profiles.

****

Method #1: AO decision: Allow Bluetooth and train users to connect only authorized Bluetooth devices.

On the management tool, in the device restrictions section, set "Bluetooth" to "Allow".

Note: Training is covered in KNOX-10-009900.

****

Method #2: AO decision: Disallow use of Bluetooth.

On the management tool, in the device restrictions section, set "Bluetooth" to "Disallow".

****

Method #3: Use KPE Bluetooth UUID Whitelisting to allow only DoD-approved profiles.

On the management tool, in the device KPE Bluetooth section, add each DoD-approved profile UUID to the "Bluetooth UUID whitelist":
- HFP (HFP_AG_UUID, HFP_UUID)
- HSP (HSP_AG_UUID, HSP_UUID)
- SPP (SPP_UUID)
- A2DP (A2DP_ADVAUDIODIST_UUID, A2DP_AUDIOSINK_UUID, A2DP_AUDIOSOURCE_UUID)
- AVRCP (AVRCP_CONTROLLER_UUID, AVRCP_TARGET_UUID)
- PBAP (PBAP_PSE_UUID, PBAP_UUID)'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44476r680239_chk'
  tag severity: 'low'
  tag gid: 'V-241200'
  tag rid: 'SV-241200r852768_rule'
  tag stig_id: 'KNOX-10-001300'
  tag gtitle: 'PP-MDF-301110'
  tag fix_id: 'F-44435r680240_fix'
  tag 'documentable'
  tag legacy: ['SV-109033', 'V-99929']
  tag cci: ['CCI-000366', 'CCI-001761']
  tag nist: ['CM-6 b', 'CM-7 (1) (b)']
end
