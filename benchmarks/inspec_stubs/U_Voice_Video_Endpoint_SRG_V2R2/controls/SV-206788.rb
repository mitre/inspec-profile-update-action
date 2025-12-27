control 'SV-206788' do
  title 'The hardware Voice Video Endpoint PC port must connect to an 802.1x supplicant, or the PC port must be disabled.'
  desc 'IEEE 802.1x is a protocol used to control access to LAN services via a network access switchport or wireless access point that requires a device or user to authenticate to the network element and become authorized by the authentication server before accessing the network. This standard is used to activate the network access switchport limiting traffic to a specific VLAN or install traffic filters. Implementing 802.1x port security on each access switchport denies all other MAC users, which eliminates the security risk of additional users attaching to a switch to bypass authentication. The hardware Voice Video Endpoint must be an 802.1x supplicant and integrate into the 802.1x access control system. When 802.1x is used, all devices connecting to the LAN are required to use 802.1x.

A Voice Video Endpoint with a PC port may break 802.1x LAN access control mechanisms when the network access switchport is authorized during the Voice Video Endpoint authentication to the network. This condition may permit devices connected to the PC port to access the LAN. The access switchport can be configured in one of the following modes: single-host, multi-host, or multi-domain. Single-host allows only one device to authenticate, and only packets from this devices MAC address will be allowed, dropping all other packets. Multi-host mode requires one host to authenticate but once this is done, all packets regardless of source MAC address will be allowed. For both the PC attached to the PC port and the Voice Video Endpoint to authenticate separately, multi-domain authentication on the access switchport must be configured. This divides the switchport into a data and a voice domain. In this case if more than one device attempts authorization on either the voice or the data domain of a port, the switchport goes into an error disable state. Disabling the PC port requires the network access switchports are configured with the appropriate VLAN for the VVoIP or VTC traffic and placing the disabled PC port traffic on the unused VLAN. MAC Address Bypass (MAB) is a possible mitigation for this vulnerability.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint with a PC port, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint PC port connects to an 802.1x supplicant or is disabled. 

If the hardware Voice Video Endpoint PC port is disabled, this is not a finding. If the hardware Voice Video Endpoint PC port is not disabled and is not an 802.1x authenticator, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint PC port to connect to an 802.1x supplicant in the implemented 802.1x network access control system or be disabled.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7044r363887_chk'
  tag severity: 'medium'
  tag gid: 'V-206788'
  tag rid: 'SV-206788r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00003'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7044r363888_fix'
  tag 'documentable'
  tag legacy: ['V-66687', 'SV-81177']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
