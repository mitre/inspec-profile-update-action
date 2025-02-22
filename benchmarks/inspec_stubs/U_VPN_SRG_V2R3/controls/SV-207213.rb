control 'SV-207213' do
  title 'The VPN Gateway must uniquely identify all network-connected endpoint devices before establishing a connection.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including, but not limited to, workstations, printers, servers (outside a datacenter), VoIP Phones, and VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.'
  desc 'check', 'Verify the VPN Gateway uniquely identifies all network-connected endpoint devices before establishing a connection.

If the VPN Gateway does not uniquely identify all network-connected endpoint devices before establishing a connection, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to uniquely identify all network-connected endpoint devices before establishing a connection.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7473r378260_chk'
  tag severity: 'medium'
  tag gid: 'V-207213'
  tag rid: 'SV-207213r608988_rule'
  tag stig_id: 'SRG-NET-000148-VPN-000540'
  tag gtitle: 'SRG-NET-000148'
  tag fix_id: 'F-7473r378261_fix'
  tag 'documentable'
  tag legacy: ['V-97097', 'SV-106235']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
