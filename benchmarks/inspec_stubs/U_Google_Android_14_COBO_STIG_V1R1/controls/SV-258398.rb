control 'SV-258398' do
  title 'Google Android 14 must be configured to enforce that Wi-Fi Sharing is disabled.'
  desc 'Wi-Fi Sharing is an optional configuration of Wi-Fi Tethering/Mobile Hotspot, which allows the device to share its Wi-Fi connection with other wirelessly connected devices instead of its mobile (cellular) connection. 
 
Wi-Fi Sharing grants the "other" device access to a corporate Wi-Fi network and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a preshared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 / WLAN #3'
  desc 'check', 'Review device configuration settings to confirm Wi-Fi Sharing is disabled. 
 
Mobile Hotspot must be enabled to enable Wi-Fi Sharing. If the Authorizing Official (AO) has not approved Mobile Hotspot, and it has been verified as disabled on the EMM console, no further action is needed. 

If Mobile Hotspot is being used, use the following procedure to verify Wi-Fi Sharing is disabled: 

On the EMM console:

COBO:

1. Open "Set user restrictions".
2. Verify "Disallow config tethering" is toggled to "ON".

COPE:

1. Open "Set user restrictions on parent".
2. Toggle "Disallow config tethering" to "ON".

On the managed Google Android 14 device:

COBO and COPE:

1. Go to Settings >> Network & Internet.
2. Verify "Hotspot & tethering" is "Controlled by admin".
3. Verify that tapping "Hotspot & tethering" provides a prompt to the user specifying "Action not allowed".
 
If on the managed Google Android 14 device "Hotspot & tethering" is enabled, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to disable Wi-Fi Sharing.
 
Mobile Hotspot must be enabled to enable Wi-Fi Sharing. If the AO has not approved Mobile Hotspot, and it has been disabled on the EMM console, no further action is needed. 

If Mobile Hotspot is being used, use the following procedure to disable Wi-Fi Sharing: 

On the EMM console:

COBO:

1. Open "Set user restrictions".
2. Toggle "Disallow config tethering" to "ON".

COPE:

1. Open "Set user restrictions on parent".
2. Toggle "Disallow config tethering" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 14 COBO'
  tag check_id: 'C-62139r928217_chk'
  tag severity: 'medium'
  tag gid: 'V-258398'
  tag rid: 'SV-258398r928219_rule'
  tag stig_id: 'GOOG-14-009900'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62063r928218_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
