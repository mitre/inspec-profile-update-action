control 'SV-91327' do
  title 'The Samsung Android 7 with Knox platform must implement the management setting: Disable Samsung WiFi Sharing.'
  desc 'WiFi Tethering allows a device to act as an Access Point sharing its data connection with other wirelessly connected devices. Previously the device could only share its Mobile (Cellular) data connection. On the Device menus this is referred to as "Mobile Hotspot". The new feature is an optional configuration of WiFi Tethering/Mobile Hotspot, which allows the Device to share its WiFi connection with other wirelessly connected devices, instead of its Mobile (Cellular) connection.

WiFi sharing grants the "other" device access to a corporate WiFi network, and may possibly bypass the network access control mechanisms. This risk can be partially mitigated by requiring the use of a pre-shared key for personal hotspots.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify WiFi Sharing is disabled or alternately, the "WiFi Tethering/Mobile Hotspot" control is disabled. 

First, determine if the AO has approved WiFi Tethering/Mobile Hotspot use. Written approval must be presented for verification of AO approval.

If there is no written AO approval that WiFi Tethering/Mobile Hotspot use do the following:
- On the MDM console, verify the "WiFi Tethering/Mobile Hotspot" control is disabled in the "WiFi Policy" rule.

If the AO has approved WiFi Tethering/Mobile Hotspot use do the following:
- On a sample of site Samsung devices, go to Settings >> Connections >> Mobile Hotspot and Tethering >> Mobile Hotspot and verify "Wi-Fi Sharing" is turned off.

Note: This setting cannot be managed by the MDM administrator and is a User Based Enforcement (UBE) requirement.

If the AO has not approved WiFi Tethering/Mobile Hotspot use and on the MDM console the "WiFi Tethering/Mobile Hotspot" control is not disabled in the "WiFi Policy" rule, this is a finding.

If the AO has approved WiFi Tethering/Mobile Hotspot use and the WiFi Sharing setting on a Samsung device is turned on, this is a finding.'
  desc 'fix', 'Disable WiFi Sharing using one of the following methods:

1. If the AO has not approved hotspot tethering for site Samsung devices, on the MDM console, select the "Disable WiFi Tethering/Mobile Hotspot"" checkbox in the "WiFi Policy" rule.
OR
2. If the AO has approved hotspot tethering for site Samsung devices, on the Samsung device go to Settings >> Connections >> Mobile Hotspot and Tethering >> Mobile Hotspot.

Turn off WiFi Sharing if it is enabled. WiFi Sharing is disabled by default.

Note: Mobile Hotspot must be enabled in order to enable WiFi Sharing.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76631'
  tag rid: 'SV-91327r1_rule'
  tag stig_id: 'KNOX-07-019200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83325r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
