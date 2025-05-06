control 'SV-108067' do
  title 'Google Android 10 must be configured to enforce that Wi-Fi Sharing is disabled.'
  desc 'Wi-Fi Sharing is an optional configuration of Wi-Fi Tethering/Mobile Hotspot, which allows the device to share its Wi-Fi connection with other wirelessly connected devices instead of its mobile (cellular) connection. 

Wi-Fi Sharing grants the "other" device access to a corporate Wi-Fi network and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a preshared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm Wi-Fi Sharing is disabled. 

Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the Authorizing Official (AO) has not approved Mobile Hotspot, and it has been verified as disabled on the MDM console, no further action is needed. If Mobile Hotspot is being used, use the following procedure to verify Wi-Fi Sharing is disabled: 

On the MDM console:
1. Open the User restrictions setting.
2. Verify "Disallow config tethering" to on.

On the Google Android 10 device, do the following: 
1. Open Settings. 
2. Tap "Networks & internet". 
3. Verify that "Hotspots & tethering" is disabled. 

If on the Google Android 10 device "Wi-Fi sharing" is enabled, this is a finding.'
  desc 'fix', 'Configure Google Android 10 to disable Wi-Fi Sharing. 

Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the AO has not approved Mobile Hotspot, and it has been disabled on the MDM console, no further action is needed. If Mobile Hotspot is being used, use the following procedure to disable Wi-Fi Sharing: 

On the MDM console:
1. Open the User restrictions setting.
2. Set "Disallow config tethering" to on.'
  impact 0.5
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-98963'
  tag rid: 'SV-108067r1_rule'
  tag stig_id: 'GOOG-10-008800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-104639r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
