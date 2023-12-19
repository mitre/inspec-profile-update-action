control 'SV-206789' do
  title 'The unused hardware Voice Video Endpoint PC port must be disabled.'
  desc 'IEEE 802.1x is a protocol used to control access to LAN services via a network access switchport or wireless access point that requires a device or user to authenticate to the network element and become authorized by the authentication server before accessing the network. This standard is used to activate the network access switchport limiting traffic to a specific VLAN or install traffic filters. Implementing 802.1x port security on each access switchport denies all other MAC users, which eliminates the security risk of additional users attaching to a switch to bypass authentication. The hardware Voice Video Endpoint must be an 802.1x supplicant and integrate into the 802.1x access control system. When 802.1x is used, all devices connecting to the LAN are required to use 802.1x.

A Voice Video Endpoint with a PC port may break 802.1x LAN access control mechanisms when the network access switchport is authorized during the Voice Video Endpoint authentication to the network. This condition may permit devices connected to the PC port to access the LAN. Daisy chaining devices on a single LAN drop protected by 802.1x must be prohibited unless the PC port is an 802.1x authenticator and configured to work with an approved authentication server. Disabling the PC port requires the network access switchports are configured with the appropriate VLAN for the VVoIP or VTC traffic and placing the disabled PC port traffic on the unused VLAN. MAC Address Bypass (MAB) is a possible mitigation for this vulnerability.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint with a PC port, this check procedure is Not Applicable.

Verify the unused hardware Voice Video Endpoint PC port is disabled. 

If the unused hardware Voice Video Endpoint PC port is not disabled, this is a finding.'
  desc 'fix', 'Configure the unused hardware Video Endpoint PC port to be disabled.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7045r363890_chk'
  tag severity: 'medium'
  tag gid: 'V-206789'
  tag rid: 'SV-206789r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00004'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7045r363891_fix'
  tag 'documentable'
  tag legacy: ['SV-81179', 'V-66689']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
