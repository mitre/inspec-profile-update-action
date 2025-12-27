control 'SV-91257' do
  title 'The Samsung Android 7 with Knox must be configured to enable authentication of personal hotspot connections to the device using a preshared key.'
  desc 'If there is no authentication required to establish personal hotspot connections, an adversary may be able to use that device to perform attacks on other devices or networks without detection. A sophisticated adversary may also be able to exploit unknown system vulnerabilities to access information and computing resources on the device. Requiring authentication to establish personal hotspot connections mitigates this risk.

Application note: If hotspot functionality is permitted, it must be authenticated via a preshared key. There is no requirement to enable hotspot functionality.

SFR ID: FMT_SMF_EXT.1.1 #41a'
  desc 'check', 'Review Samsung Android 7 with Knox configuration settings to determine if the mobile device has enabled authentication of personal hotspot connections to the device using a preshared key. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device. 

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow Unsecured Hotspot" checkbox in the "WiFi Policy" rule. 
2. Verify the checkbox is not selected.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Select "Mobile hotspot and tethering".
3. Select "Mobile hotspot".
4. Select "Configure Mobile hotspot" more options.
5. Verify that user cannot save configuration with security set to "Open".

If the MDM console "Allow Unsecured Hotspot" checkbox is selected or on the Samsung Android 7 with Knox device, can be configured as a Mobile Hotspot with Open Security, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enable authentication of personal hotspot connections to the device using a preshared key.

On the MDM console, deselect the "Allow Unsecured Hotspot" checkbox in the "WiFi Policy" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76227r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76561'
  tag rid: 'SV-91257r1_rule'
  tag stig_id: 'KNOX-07-005100'
  tag gtitle: 'PP-MDF-301240'
  tag fix_id: 'F-83255r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
