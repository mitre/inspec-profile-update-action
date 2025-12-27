control 'SV-207141' do
  title 'The out-of-band management (OOBM) gateway must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.'
  desc 'Using dedicated paths, the OOBM backbone connects the OOBM gateway routers located at the edge of the managed network and at the NOC. Dedicated links can be deployed using provisioned circuits or MPLS Layer 2 and Layer 3 VPN services or implementing a secured path with gateway-to-gateway IPsec tunnels. The tunnel mode ensures that the management traffic will be logically separated from any other traffic traversing the same path.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC.

Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses.

If management traffic is not transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Ensure that a dedicated circuit, MPLS/VPN service, or IPsec tunnel is deployed to transport management traffic between the managed network and the NOC.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7402r382361_chk'
  tag severity: 'medium'
  tag gid: 'V-207141'
  tag rid: 'SV-207141r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000009'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7402r382362_fix'
  tag 'documentable'
  tag legacy: ['V-78255', 'SV-92961']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
