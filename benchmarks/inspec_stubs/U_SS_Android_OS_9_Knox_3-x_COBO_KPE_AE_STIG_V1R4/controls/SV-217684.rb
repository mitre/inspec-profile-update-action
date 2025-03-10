control 'SV-217684' do
  title 'Samsung Android must be configured to enforce that Wi-Fi Sharing is disabled.'
  desc 'Wi-Fi Sharing is an optional configuration of Wi-Fi Tethering/Mobile Hotspot, which allows the device to share its Wi-Fi connection with other wirelessly connected devices instead of its mobile (cellular) connection. 

Wi-Fi Sharing grants the "other" device access to a corporate Wi-Fi network and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a preshared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm Wi-Fi Sharing is disabled. 

Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the Authorizing Official (AO) has not approved Mobile Hotspot, and it has been verified as disabled on the MDM console, the following guidance is not applicable. 

This setting cannot be managed by the MDM administrator and is a User-Based Enforcement (UBE) requirement. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Connections". 
3. Tap "Mobile Hotspot and Tethering". 
4. Tap "Mobile hotspot". 
5. Verify that "Wi-Fi sharing" is disabled. 

If on the Samsung Android device "Wi-Fi sharing" is enabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable Wi-Fi Sharing. 

Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the AO has not approved Mobile Hotspot, and it has been disabled on the MDM console, the following guidance is not applicable. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Connections". 
3. Tap "Mobile Hotspot and Tethering". 
4. Tap "Mobile hotspot". 
5. Disable "Wi-Fi sharing" if it is enabled.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18903r362081_chk'
  tag severity: 'medium'
  tag gid: 'V-217684'
  tag rid: 'SV-217684r388482_rule'
  tag stig_id: 'KNOX-09-000820'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18901r362082_fix'
  tag 'documentable'
  tag legacy: ['SV-102993', 'V-92905']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
