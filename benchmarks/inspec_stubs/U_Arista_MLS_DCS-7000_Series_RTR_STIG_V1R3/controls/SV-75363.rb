control 'SV-75363' do
  title 'The Arista Multilayer Switch must enforce that Interior Gateway Protocol instances configured on the out-of-band management gateway router only peer with their own routing domain.'
  desc 'If the gateway router is not a dedicated device for the out-of-band management network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate Interior Gateway Protocol routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'Verify that the out-of-band management interface is an adjacency in the Interior Gateway Protocol routing domain for the management network. This requirement does not apply to in-band management networks.

The out-of-band management interface will not form an adjacency with the IGP running on the switch. If the Arista MLS is acting as the gateway for the management network, and management traffic is ingressing the switch via in-band dataplane interfaces, these interfaces may be in a dedicated VRF for the management network. To verify this VRF, run a "show vrf" and confirm the interfaces handling management traffic are displayed in the resulting output. Alternatively, if VRFs are not used, the management network must use a separate routing domain that is not advertised or redistributed to the managed network. This can be verified by checking the relevant configuration statements for the routing protocol instances and ensuring no redistribute statement exists that will bridge the managed and management networks.

Using the "show ip route" command will also verify this requirement by displaying the routing tables. Stipulating the VRF via the "show ip route vrf [name]" will display a separate routing table for a configured VRF, distinct from the default routing table in the default VRF, provided by the "show ip route" command with an unspecified VRF.

If the router does not enforce that Interior Gateway Protocol instances configured on the out-of-band management gateway router only peer with their own routing domain, this is a finding.'
  desc 'fix', 'Configure the router to enforce that Interior Gateway Protocol instances configured on the out-of-band management gateway router only peer with their own routing domain.

To configure a management vrf, enter the following from the configuration mode:
vrf definition [name]
rd [AS#]:[local assignment]

Then, from the interface configuration mode, assign the interface to the VRF:
interface [type][number]
vrf forwarding [vrf name]

Then enable IP routing for the VRF:
ip routing vrf [name]

Then, from the IGP configuration mode interface, configure the routing protocols.
router [protocol] [processID]
vrf [name]
[configuration statement]

To remove offending redistribute statements, enter the command:
no redistribute [connected/ospf/bgp/etc]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61851r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60905'
  tag rid: 'SV-75363r1_rule'
  tag stig_id: 'AMLS-L3-000180'
  tag gtitle: 'SRG-NET-000019-RTR-000012'
  tag fix_id: 'F-66617r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
