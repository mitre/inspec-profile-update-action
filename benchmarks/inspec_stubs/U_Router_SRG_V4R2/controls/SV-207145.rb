control 'SV-207145' do
  title 'The router providing connectivity to the NOC must be configured to forward all in-band management traffic via an IPsec tunnel.'
  desc 'When the production network is managed in-band, the management network could be housed at a NOC that is located remotely at single or multiple interconnected sites. NOC interconnectivity, as well as connectivity between the NOC and the managed network, must be enabled using IPsec tunnels to provide the separation and integrity of the managed traffic.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Verify that all traffic from the managed network to the management network and vice-versa is secured via IPsec tunnel.

If the management traffic is not secured via IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Ensure that all traffic from the managed network to the management network and vice-versa is secured via IPsec tunnel.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7406r382418_chk'
  tag severity: 'medium'
  tag gid: 'V-207145'
  tag rid: 'SV-207145r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000013'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7406r382419_fix'
  tag 'documentable'
  tag legacy: ['SV-92969', 'V-78263']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
