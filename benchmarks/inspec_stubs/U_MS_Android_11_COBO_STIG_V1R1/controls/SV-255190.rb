control 'SV-255190' do
  title 'Microsoft Android 11 must be configured to enforce that Wi-Fi Sharing is disabled.'
  desc 'Wi-Fi Sharing is an optional configuration of Wi-Fi Tethering/Mobile Hotspot, which allows the device to share its Wi-Fi connection with other wirelessly connected devices instead of its mobile (cellular) connection. 
 
Wi-Fi Sharing grants the "other" device access to a corporate Wi-Fi network and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a preshared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm Wi-Fi Sharing is disabled. 
 
Mobile Hotspot must be enabled to enable Wi-Fi Sharing. If the Authorizing Official (AO) has not approved Mobile Hotspot, and it has been verified as disabled on the EMM console, no further action is needed. If Mobile Hotspot is being used, use the following procedure to verify Wi-Fi Sharing is disabled: 

On the EMM console:
1. Open "Set user restrictions on parent".
2. Verify that "Disallow config tethering" is toggled to "On".

On the Microsoft Android 11 device: 
1. Open "Settings". 
2. Tap "Networks & internet". 
3. Verify that "Hotspots & tethering" is disabled. 
 
If on the Microsoft Android 11 device "Wi-Fi sharing" is enabled, this is a finding.'
  desc 'fix', 'Configure Microsoft Android 11 device to disable Wi-Fi Sharing. 
 
Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the AO has not approved Mobile Hotspot, and it has been disabled on the EMM console, no further action is needed. If Mobile Hotspot is being used, use the following procedure to disable Wi-Fi Sharing: 

On the EMM console:
1. Open "Set user restrictions on parent".
2. Toggle "Disallow config tethering" to "On".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58803r870790_chk'
  tag severity: 'medium'
  tag gid: 'V-255190'
  tag rid: 'SV-255190r870791_rule'
  tag stig_id: 'MSFT-11-008800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58747r869432_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
