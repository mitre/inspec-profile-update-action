control 'SV-207116' do
  title 'The out-of-band management (OOBM) gateway router must be configured to have separate IGP instances for the managed network and management network.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate Interior Gateway Protocol routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Verify that the OOBM interface is an adjacency in the Interior Gateway Protocol routing domain for the management network.

If the router does not enforce that Interior Gateway Protocol instances configured on the OOBM gateway router peer only with their own routing domain, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router to enforce that Interior Gateway Protocol instances configured on the OOBM gateway router peer only with their own routing domain.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7377r382241_chk'
  tag severity: 'medium'
  tag gid: 'V-207116'
  tag rid: 'SV-207116r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000011'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7377r382242_fix'
  tag 'documentable'
  tag legacy: ['SV-69993', 'V-55739']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
