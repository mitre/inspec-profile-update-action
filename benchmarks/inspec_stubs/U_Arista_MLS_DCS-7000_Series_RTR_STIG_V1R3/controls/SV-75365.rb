control 'SV-75365' do
  title 'The Arista Multilayer Switch must enforce that the managed network domain and the management network domain are separate routing domains and the Interior Gateway Protocol instances are not redistributed or advertised to each other.'
  desc 'If the gateway router is not a dedicated device for the out-of-band management network, several safeguards must be implemented for containment of management and production traffic boundaries; otherwise, it is possible that management traffic will not be separated from production traffic. 

Since the managed network and the management network are separate routing domains, separate Interior Gateway Protocol routing instances must be configured on the router, one for the managed network and one for the out-of-band management network. In addition, the routes from the two domains must not be redistributed to each other.'
  desc 'check', 'Verify the Interior Gateway Protocol instance used for the managed network does not redistribute routes into the Interior Gateway Protocol instance used for the management network, and vice versa.

This can be verified via the "show run section [routing protocol]" command. The output of this command will display the active configuration for the routing protocol on the switch. Verify the routing protocol configuration does not contain a statement redistributing or advertising routes from the managed domain into the management domain, or vice versa.

Using the "show ip route" command will also verify this requirement by displaying the routing tables. Stipulating the VRF via the "show ip route vrf [name]" will display a separate routing table for a configured VRF, distinct from the default routing table in the default VRF, provided by the "show ip route" command with an unspecified VRF.

If the Interior Gateway Protocol instance used for the managed network redistributes routes into the Interior Gateway Protocol instance used for the management network, or vice versa, this is a finding.'
  desc 'fix', 'Configure the Interior Gateway Protocol instance used for the managed network to prohibit redistribution of routes into the Interior Gateway Protocol instance used for the management network, and vice versa.

This can be configured via the VRF configuration provided in SRG-NET-000019-RTR-000012.'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60907'
  tag rid: 'SV-75365r1_rule'
  tag stig_id: 'AMLS-L3-000190'
  tag gtitle: 'SRG-NET-000019-RTR-000013'
  tag fix_id: 'F-66619r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
