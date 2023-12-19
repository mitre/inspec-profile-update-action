control 'SV-250406' do
  title 'Google Android 12 must be configured to enforce that Wi-Fi Sharing is disabled.'
  desc 'Wi-Fi Sharing is an optional configuration of Wi-Fi Tethering/Mobile Hotspot, which allows the device to share its Wi-Fi connection with other wirelessly connected devices instead of its mobile (cellular) connection. 
 
Wi-Fi Sharing grants the "other" device access to a corporate Wi-Fi network and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a preshared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm Wi-Fi Sharing is disabled. 
 
Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the Authorizing Official (AO) has not approved Mobile Hotspot, and it has been verified as disabled on the EMM console, no further action is needed. 

If Mobile Hotspot is being used, use the following procedure to verify Wi-Fi Sharing is disabled: 

On the EMM console:

COBO:

1. Open "Set user restrictions".
2. Verify that "Disallow config tethering" is toggled to ON.

COPE:

1. Open "Set user restrictions on parent".
2. Toggle "Disallow config tethering" to ON.

On the managed Google Android 12 device:

COBO and COPE:

1. Go to Settings >> Network & Internet.
2. Verify that "Hotspot & tethering" is "Controlled by admin".
3. Verify that tapping "Hotspot & tethering" provides a prompt to the user specifying "Action not allowed".
 
If on the managed Google Android 12 device "Hotspot & tethering" is enabled, this is a finding.'
  desc 'fix', 'Configure the Google Android 12 device to disable Wi-Fi Sharing.
 
Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the AO has not approved Mobile Hotspot, and it has been disabled on the EMM console, no further action is needed. 

If Mobile Hotspot is being used, use the following procedure to disable Wi-Fi Sharing: 

On the EMM console:

COBO:

1. Open "Set user restrictions".
2. Toggle "Disallow config tethering" to ON.

COPE:

1. Open "Set user restrictions on parent".
2. Toggle "Disallow config tethering" to ON.'
  impact 0.5
  ref 'DPMS Target Google Android 12 COBO'
  tag check_id: 'C-53841r796724_chk'
  tag severity: 'medium'
  tag gid: 'V-250406'
  tag rid: 'SV-250406r802763_rule'
  tag stig_id: 'GOOG-12-009900'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-53795r796725_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
