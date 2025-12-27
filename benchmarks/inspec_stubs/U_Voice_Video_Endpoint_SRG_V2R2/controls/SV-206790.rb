control 'SV-206790' do
  title 'The hardware Voice Video Endpoint with a PC port must have the switchport configured as single-host or enable 802.1x multi-domain authentication.'
  desc 'IEEE 802.1x is a protocol used to control access to LAN services via a network access switchport or wireless access point that requires a device or user to authenticate to the network element and become authorized by the authentication server before accessing the network. This standard is used to activate the network access switchport limiting traffic to a specific VLAN or install traffic filters. Implementing 802.1x port security on each access switchport denies all other MAC users, which eliminates the security risk of additional users attaching to a switch to bypass authentication. The hardware Voice Video Endpoint must be an 802.1x supplicant and integrate into the 802.1x access control system. When 802.1x is used, all devices connecting to the LAN are required to use 802.1x.

A Voice Video Endpoint with a PC port may break 802.1x LAN access control mechanisms when the network access switchport is authorized during the Voice Video Endpoint authentication to the network. This condition may permit devices connected to the PC port to access the LAN. Daisy chaining devices on a single LAN drop protected by 802.1x must be prohibited unless the PC port is an 802.1x authenticator and configured to work with an approved authentication server. Disabling the PC port requires the network access switchports are configured with the appropriate VLAN for the VVoIP or VTC traffic and placing the disabled PC port traffic on the unused VLAN. MAC Address Bypass (MAB) is a possible mitigation for this vulnerability.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint with a PC port, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint with a PC port has the switchport configured as single-host or enable 802.1x multi-domain authentication. 

If the hardware Voice Video Endpoint with a PC port has the switchport configured as single-host, this is not a finding. 

If the hardware Voice Video Endpoint with a PC port does not have the switchport configured as single-host and does not enable 802.1x multi-domain authentication, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint with a PC port to have the switchport configured as single-host or enable 802.1x multi-domain authentication.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7046r363893_chk'
  tag severity: 'medium'
  tag gid: 'V-206790'
  tag rid: 'SV-206790r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00005'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7046r363894_fix'
  tag 'documentable'
  tag legacy: ['SV-81181', 'V-66691']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
