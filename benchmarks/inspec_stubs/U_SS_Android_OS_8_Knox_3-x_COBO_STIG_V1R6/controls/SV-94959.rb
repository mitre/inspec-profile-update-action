control 'SV-94959' do
  title 'Samsung Android 8 with Knox must be configured to enable authentication of personal hotspot connections to the device using a pre-shared key.'
  desc 'If no authentication is required to establish personal hotspot connections, an adversary may be able to use that device to perform attacks on other devices or networks without detection. A sophisticated adversary may also be able to exploit unknown system vulnerabilities to access information and computing resources on the device. Requiring authentication to establish personal hotspot connections mitigates this risk.

Application note: If hotspot functionality is permitted, it must be authenticated via a pre-shared key. There is no requirement to enable hotspot functionality.

SFR ID: FMT_SMF_EXT.1.1 #41a'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has enabled authentication of personal hotspot connections to the device using a pre-shared key. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device. 

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow Unsecured Hotspot" check box in the "WiFi Policy" rule. 
2. Verify the check box is not selected.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Connections".
3. Select "Mobile Hotspot and Tethering".
4. Select "Mobile hotspot".
5. Select "Configure Mobile hotspot" more options.
6. Verify the user cannot save the configuration with security set to "Open".

If the MDM console "Allow Unsecured Hotspot" check box is selected or the Samsung Android 8 with Knox device can be configured as a Mobile Hotspot with Open Security, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enable authentication of personal hotspot connections to the device using a pre-shared key.

On the MDM console, deselect the "Allow Unsecured Hotspot" check box in the "WiFi Policy" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79927r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80255'
  tag rid: 'SV-94959r1_rule'
  tag stig_id: 'KNOX-08-018100'
  tag gtitle: 'PP-MDF-301240'
  tag fix_id: 'F-87061r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
