control 'SV-207117' do
  title 'The out-of-band management (OOBM) gateway router must be configured to not redistribute routes between the management network routing domain and the managed network routing domain.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries; otherwise, it is possible that management traffic will not be separated from production traffic.

Since the managed network and the management network are separate routing domains, separate Interior Gateway Protocol routing instances must be configured on the router, one for the managed network and one for the OOBM network. In addition, the routes from the two domains must not be redistributed to each other.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Verify the Interior Gateway Protocol instance used for the managed network does not redistribute routes into the Interior Gateway Protocol instance used for the management network, and vice versa.

If the Interior Gateway Protocol instance used for the managed network redistributes routes into the Interior Gateway Protocol instance used for the management network, or vice versa, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the Interior Gateway Protocol instance used for the managed network to prohibit redistribution of routes into the Interior Gateway Protocol instance used for the management network, and vice versa.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7378r382244_chk'
  tag severity: 'medium'
  tag gid: 'V-207117'
  tag rid: 'SV-207117r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000012'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7378r382245_fix'
  tag 'documentable'
  tag legacy: ['V-55741', 'SV-69995']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
