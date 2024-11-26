control 'SV-231031' do
  title 'Samsung Android must be configured to enable authentication of personal hotspot connections to the device using a pre-shared key.'
  desc 'If no authentication is required to establish personal hotspot connections, an adversary may be able to use that device to perform attacks on other devices or networks without detection. A sophisticated adversary may also be able to exploit unknown system vulnerabilities to access information and computing resources on the device. Requiring authentication to establish personal hotspot connections mitigates this risk.

Application note: If hotspot functionality is permitted, it must be authenticated via a pre-shared key. There is no requirement to enable hotspot functionality.

SFR ID: FMT_SMF_EXT.1.1 #41a'
  desc 'check', 'Review Samsung Android configuration settings to determine if the mobile device has enabled authentication of personal hotspot connections to the device using a pre-shared key. 

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device Wi-Fi section, verify that "Unsecured hotspot" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Connections >> Mobile Hotspot and Tethering >> Mobile Hotspot >> Edit.
2. Tap option "Open" in the "Security" drop-down box.
3. Verify that "Save" is disabled.

If on the management tool "Unsecured hotspot" is not set to "Disallow", or on the Samsung Android device "Open" can be selected in the "Security" drop-down box and the configuration can be saved, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable authentication of personal hotspot connections to the device using a pre-shared key.

On the management tool, in the device Wi-Fi section, set "Unsecured hotspot" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33961r592707_chk'
  tag severity: 'medium'
  tag gid: 'V-231031'
  tag rid: 'SV-231031r608683_rule'
  tag stig_id: 'KNOX-11-008200'
  tag gtitle: 'PP-MDF-301240'
  tag fix_id: 'F-33934r592708_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
