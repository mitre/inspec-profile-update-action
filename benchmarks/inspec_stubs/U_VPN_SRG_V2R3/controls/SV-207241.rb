control 'SV-207241' do
  title 'The VPN Gateway must authenticate all network-connected endpoint devices before establishing a connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including, but not limited to, workstations, printers, servers (outside a datacenter), VoIP Phones, and VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.

Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system.'
  desc 'check', 'Verity the VPN Gateway  authenticates all network-connected endpoint devices before establishing a connection.

If the VPN Gateway does not authenticate all network-connected endpoint devices before establishing a connection, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to authenticate all network-connected endpoint devices before establishing a connection.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7501r378344_chk'
  tag severity: 'medium'
  tag gid: 'V-207241'
  tag rid: 'SV-207241r608988_rule'
  tag stig_id: 'SRG-NET-000343-VPN-001370'
  tag gtitle: 'SRG-NET-000343'
  tag fix_id: 'F-7501r378345_fix'
  tag 'documentable'
  tag legacy: ['SV-106315', 'V-97177']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
