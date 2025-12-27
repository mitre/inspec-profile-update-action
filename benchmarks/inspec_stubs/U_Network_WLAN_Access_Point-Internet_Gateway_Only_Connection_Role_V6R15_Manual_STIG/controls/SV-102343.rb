control 'SV-102343' do
  title 'DoD Components providing guest WLAN access (Internet access only) must use separate WLAN or logical segmentation of the enterprise WLAN (e.g., separate service set identifier (SSID) and virtual LAN) or DoD network.'
  desc 'The purpose of the Guest WLAN network is to provide WLAN services to authorized site guests. Guests, by definition, are not authorized access to the enterprise network. If the guest WLAN is not correctly installed unauthorized access to the enterprise wireless and/or wired network could be obtained.'
  desc 'check', 'Have the SA show how the guest WLAN is physically connected to the firewall or supporting switch and how it is logically connected through firewall or switch configuration settings.

Verify the equipment is connected via a separate WLAN or logical segmentation of the host WLAN (e.g., separate service set identifier (SSID) and virtual LAN).

Verify the guest WLAN only provides Internet access.

If a guest WLAN is not set up as a separate WLAN from the DoD network or not set up as a logical segmentation from the DoD network or DoD WLAN, this is a finding.

If the guest WLAN does not only provide Internet access, this is a finding.'
  desc 'fix', 'Reconfigure physical and logical connections as needed so the Internet-only guest WLAN infrastructure resides in a dedicated subnet off the perimeter firewall or installed as a completely separate Internet-connection only WLAN system with no access to the enterprise network.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-91407r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92241'
  tag rid: 'SV-102343r1_rule'
  tag stig_id: 'WIR0123-1'
  tag gtitle: 'Guest WLAN infrastructure placement'
  tag fix_id: 'F-98449r1_fix'
  tag 'documentable'
end
