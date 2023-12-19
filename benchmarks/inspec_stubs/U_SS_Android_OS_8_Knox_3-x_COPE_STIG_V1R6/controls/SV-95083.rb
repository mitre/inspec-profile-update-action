control 'SV-95083' do
  title 'Samsung Android 8 with Knox for Android must implement the management setting: Disable Samsung Wi-Fi Sharing.'
  desc 'Wi-Fi Tethering allows a device to act as an Access Point, sharing its data connection with other wirelessly connected devices. Previously the device could only share its mobile (cellular) data connection. On the Device menus, this is referred to as "Mobile Hotspot". The new feature is an optional configuration of Wi-Fi Tethering/Mobile Hotspot, which allows the device to share its Wi-Fi connection with other wirelessly connected devices instead of its mobile (cellular) connection.

Wi-Fi sharing grants the "other" device access to a corporate Wi-Fi network and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a pre-shared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify Wi-Fi Sharing is disabled or alternately, the "Wi-Fi Tethering/Mobile Hotspot" control is disabled.

Determine if the Authorizing Official (AO) has approved Wi-Fi Tethering/Mobile Hotspot use. Written approval must be presented for verification of AO approval.

If there is no written AO approval for Wi-Fi Tethering/Mobile Hotspot use, do the following:
On the MDM console, verify the "Wi-Fi Tethering/Mobile Hotspot" control is disabled in the "WiFi Policy" rule.

If the AO has approved Wi-Fi Tethering/Mobile Hotspot use, do the following:
On a sample of site Samsung devices, go to Settings >> Connections >> Mobile Hotspot and Tethering >> Mobile Hotspot and verify "Wi-Fi Sharing" is turned off.

Note: This setting cannot be managed by the MDM Administrator and is a User Based Enforcement (UBE) requirement.

If the AO has not approved Wi-Fi Tethering/Mobile Hotspot use and on the MDM console the "Wi-Fi Tethering/Mobile Hotspot" control is not disabled in the "WiFi Policy" rule, this is a finding.

If the AO has approved Wi-Fi Tethering/Mobile Hotspot use and the "Wi-Fi Sharing" setting on a Samsung device is turned on, this is a finding.'
  desc 'fix', 'Disable Wi-Fi Sharing using one of the following methods:

1. If the AO has not approved hotspot tethering for site Samsung devices, on the MDM console, select the "Disable Wi-Fi Tethering/Mobile Hotspot"" check box in the "WiFi Policy" rule.

2. If the AO has approved hotspot tethering for site Samsung devices, on the Samsung device, go to Settings >> Connections >> Mobile Hotspot and Tethering >> Mobile hotspot. Turn off "Wi-Fi Sharing" if it is enabled. 

Note: Mobile Hotspot must be enabled in order to enable Wi-Fi Sharing. Wi-Fi Sharing is disabled by default.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80051r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80379'
  tag rid: 'SV-95083r1_rule'
  tag stig_id: 'KNOX-08-016800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87185r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
