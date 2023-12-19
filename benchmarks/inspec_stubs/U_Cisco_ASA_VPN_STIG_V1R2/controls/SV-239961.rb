control 'SV-239961' do
  title 'The Cisco ASA VPN gateway must be configured to identify all peers before establishing a connection.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including, but not limited to, workstations, printers, servers (outside a datacenter), VoIP Phones, and VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.'
  desc 'check', 'Verify the VPN Gateway authenticate all peers before establishing a connection as shown in the example below. 

tunnel-group x.x.x.x type ipsec-l2l
tunnel-group x.x.x.x ipsec-attributes
 ikev2 remote-authentication pre-shared-key *****
 ikev2 local-authentication pre-shared-key *****

Note: Authentication can be either pre-shared key or certificate.

If the VPN Gateway does not uniquely identify and authenticate all peers establishing a connection, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to authenticate all peers before establishing a connection.

ASA1(config)# tunnel-group x.x.x.x type ipsec-l2l
ASA1(config)# tunnel-group x.x.x.x ipsec-attributes
ASA1(config-tunnel-ipsec)# ikev2 remote-authentication pre-shared-key xxxxxxx
ASA1(config-tunnel-ipsec)# ikev2 local-authentication pre-shared-key xxxxxxx
ASA1(config-tunnel-ipsec)# end

Note: The password complexity of pre-shared keys must be in compliance with NIST SP 800-53 control IA-5.'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43194r666287_chk'
  tag severity: 'medium'
  tag gid: 'V-239961'
  tag rid: 'SV-239961r666289_rule'
  tag stig_id: 'CASA-VN-000310'
  tag gtitle: 'SRG-NET-000148-VPN-000540'
  tag fix_id: 'F-43153r666288_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
