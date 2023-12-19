control 'SV-231008' do
  title 'Samsung Android Work Environment must be configured to enforce that Wi-Fi Sharing is disabled.'
  desc 'Wi-Fi Sharing is an optional configuration of Wi-Fi Tethering/Mobile Hotspot, which allows the device to share its Wi-Fi connection with other wirelessly connected devices instead of its mobile (cellular) connection.

Wi-Fi Sharing grants the "other" device access to a corporate Wi-Fi network and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a pre-shared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android device configuration settings to confirm that Wi-Fi Sharing is disabled.

Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the AO has not approved Mobile Hotspot, and it has been verified as disabled on the management tool, the following guidance is not applicable.

This setting cannot be managed by the management tool Administrator and is a User Based Enforcement (UBE) requirement.

On the Samsung Android device: 
1. Open Settings >> Connections >> Mobile Hotspot and Tethering >> Mobile hotspot.
2. Verify that "Wi-Fi sharing" is disabled.

If on the Samsung Android device "Wi-Fi sharing" is enabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable Wi-Fi Sharing.

Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. If the AO has not approved Mobile Hotspot, and it has been disabled on the management tool, the following guidance is not applicable.

On the Samsung Android device: 
1. Open Settings >> Connections >> Mobile Hotspot and Tethering >> Mobile hotspot.
2. Disable "Wi-Fi sharing" if it is enabled.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33938r592516_chk'
  tag severity: 'medium'
  tag gid: 'V-231008'
  tag rid: 'SV-231008r607691_rule'
  tag stig_id: 'KNOX-11-022100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33911r592517_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
