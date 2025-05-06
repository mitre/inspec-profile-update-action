control 'SV-206786' do
  title 'The hardware Voice Video Endpoint must integrate into the implemented 802.1x network access control system.'
  desc 'IEEE 802.1x is a protocol used to control access to LAN services via a network access switchport or wireless access point that requires a device or user to authenticate to the network element and become authorized by the authentication server before accessing the network. This standard is used to activate the network access switchport limiting traffic to a specific VLAN or install traffic filters. Implementing 802.1x port security on each access switchport denies all other MAC users, which eliminates the security risk of additional users attaching to a switch to bypass authentication. The hardware Voice Video Endpoint must be an 802.1x supplicant and integrate into the 802.1x access control system. When 802.1x is used, all devices connecting to the LAN are required to use 802.1x.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint integrates into the implemented 802.1x network access control system. 

If the hardware Voice Video Endpoint does not integrate into the implemented 802.1x network access control system, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint to integrate into the implemented 802.1x network access control system.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7042r363881_chk'
  tag severity: 'medium'
  tag gid: 'V-206786'
  tag rid: 'SV-206786r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00001'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7042r363882_fix'
  tag 'documentable'
  tag legacy: ['V-66683', 'SV-81173']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
