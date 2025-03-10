control 'SV-217824' do
  title 'Samsung Android must be configured to enable authentication of personal hotspot connections to the device using a preshared key.'
  desc 'If no authentication is required to establish personal hotspot connections, an adversary may be able to use that device to perform attacks on other devices or networks without detection. A sophisticated adversary may also be able to exploit unknown system vulnerabilities to access information and computing resources on the device. Requiring authentication to establish personal hotspot connections mitigates this risk. 

Application note: If hotspot functionality is permitted, it must be authenticated via a preshared key. There is no requirement to enable hotspot functionality.

SFR ID: FMT_SMF_EXT.1.1 #41a'
  desc 'check', 'Review device configuration to confirm that unsecured hotspots are disallowed. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox Wifi" group, verify that "allow unsecured hotspot" is not selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Connections". 
3. Tap "Mobile Hotspot and Tethering". 
4. Tap "Mobile Hotspot". 
5. Tap Overflow menu (three vertical dots). 
6. Tap "Configure Mobile Hotspot". 
7. Tap "Open in Security drop down". 
8. Verify that "Save" is disabled. 

If on the MDM console "allow unsecured hotspot" is selected, or on the Samsung Android device an Open Mobile Hotspot configuration can be saved, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disallow unsecured hotspots. 

On the MDM console, in the Knox Wifi restrictions, unselect "allow unsecured hotspot".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-19040r362930_chk'
  tag severity: 'medium'
  tag gid: 'V-217824'
  tag rid: 'SV-217824r617464_rule'
  tag stig_id: 'KNOX-09-000945'
  tag gtitle: 'PP-MDF-301240'
  tag fix_id: 'F-19038r362931_fix'
  tag 'documentable'
  tag legacy: ['SV-103995', 'V-93909']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
