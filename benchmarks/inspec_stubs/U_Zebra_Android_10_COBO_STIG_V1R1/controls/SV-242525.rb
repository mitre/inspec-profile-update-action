control 'SV-242525' do
  title 'Zebra Android 10 must be configured to enforce that Wi-Fi Sharing is disabled.'
  desc 'Wi-Fi Sharing is an optional configuration of Wi-Fi Tethering/Mobile Hotspot, which allows the device to share its Wi-Fi connection with other wirelessly connected devices instead of its mobile (cellular) connection. 
 
Wi-Fi Sharing grants the "other" device access to a corporate Wi-Fi network and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a pre-shared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm Wi-Fi Sharing is disabled. 
 
Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the Authorizing Official (AO) has not approved Mobile Hotspot, and it has been verified as disabled on the MDM console, no further action is needed. If Mobile Hotspot is being used, use the following procedure to verify Wi-Fi Sharing is disabled: 

On the MDM console:
1. Open the User restrictions setting.
2. Verify "Disallow config tethering" is set to On.

On the Zebra Android 10 device: 
1. Open Settings. 
2. Tap "Networks & internet". 
3. Verify that "Hotspots & tethering" is disabled. 
 
If on the Zebra Android 10 device "Wi-Fi sharing" is enabled, this is a finding.'
  desc 'fix', 'Configure Zebra Android 10 to disable Wi-Fi Sharing. 
 
Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the AO has not approved Mobile Hotspot, and it has been disabled on the MDM console, no further action is needed. If Mobile Hotspot is being used, use the following procedure to disable Wi-Fi Sharing: 

On the MDM console:
1. Open the User restrictions setting.
2. Set "Disallow config tethering" to On.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45800r714418_chk'
  tag severity: 'medium'
  tag gid: 'V-242525'
  tag rid: 'SV-242525r714420_rule'
  tag stig_id: 'ZEBR-10-008800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-45757r714419_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
