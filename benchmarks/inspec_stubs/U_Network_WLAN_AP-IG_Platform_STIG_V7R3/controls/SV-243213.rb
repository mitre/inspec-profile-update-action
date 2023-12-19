control 'SV-243213' do
  title 'DoD Components providing guest WLAN access (internet access only) must use separate WLAN or logical segmentation of the enterprise WLAN (e.g., separate service set identifier [SSID] and virtual LAN) or DoD network.'
  desc 'The purpose of the Guest WLAN network is to provide WLAN services to authorized site guests. Guests, by definition, are not authorized access to the enterprise network. If the guest WLAN is not installed correctly, unauthorized access to the enterprise wireless and/or wired network could be obtained.'
  desc 'check', 'Have the SA show how the guest WLAN is physically connected to the firewall or supporting switch and how it is logically connected through firewall or switch configuration settings.

Verify the equipment is connected via a separate WLAN or logical segmentation of the host WLAN (e.g., separate service set identifier [SSID] and virtual LAN).

Verify the guest WLAN only provides internet access.

If a guest WLAN is not set up as a separate WLAN from the DoD network or is not set up as a logical segmentation from the DoD network or DoD WLAN, this is a finding.

If the guest WLAN does not provide only internet access, this is a finding.'
  desc 'fix', 'Reconfigure physical and logical connections as needed so the internet-only guest WLAN infrastructure resides in a dedicated subnet off the perimeter firewall or is installed as a completely separate internet-connection-only WLAN system with no access to the enterprise network.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-IG Platform'
  tag check_id: 'C-46488r720092_chk'
  tag severity: 'medium'
  tag gid: 'V-243213'
  tag rid: 'SV-243213r720094_rule'
  tag stig_id: 'WLAN-NW-001000'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-46445r720093_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
