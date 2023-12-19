control 'SV-206791' do
  title 'The hardware Voice Video Endpoint not supporting 802.1x must be configured to use MAC Authentication Bypass (MAB) on the access switchport.'
  desc 'IEEE 802.1x is a protocol used to control access to LAN services via a network access switchport or wireless access point that requires a device or user to authenticate to the network element and become authorized by the authentication server before accessing the network. This standard is used to activate the network access switchport limiting traffic to a specific VLAN or install traffic filters. Implementing 802.1x port security on each access switchport denies all other MAC users, which eliminates the security risk of additional users attaching to a switch to bypass authentication. The hardware Voice Video Endpoint must be an 802.1x supplicant and integrate into the 802.1x access control system. When 802.1x is used, all devices connecting to the LAN are required to use 802.1x.

A Voice Video Endpoint with a PC port may break 802.1x LAN access control mechanisms when the network access switchport is authorized during the Voice Video Endpoint authentication to the network. This condition may permit devices connected to the PC port to access the LAN. Daisy chaining devices on a single LAN drop protected by 802.1x must be prohibited unless the PC port is an 802.1x authenticator and configured to work with an approved authentication server. Disabling the PC port requires the network access switchports are configured with the appropriate VLAN for the VVoIP or VTC traffic and placing the disabled PC port traffic on the unused VLAN. MAC Address Bypass (MAB) is a possible mitigation for this vulnerability.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint not supporting 802.1x is configured to use MAB on the access switchport. 

If the hardware Voice Video Endpoint not supporting 802.1x is not configured to use MAB on the access switchport, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint not supporting 802.1x to use MAB on the access switchport.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7047r363896_chk'
  tag severity: 'medium'
  tag gid: 'V-206791'
  tag rid: 'SV-206791r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00006'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7047r363897_fix'
  tag 'documentable'
  tag legacy: ['SV-81183', 'V-66693']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
