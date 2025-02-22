control 'SV-88789' do
  title 'The Cisco IOS XE router must enforce that the managed network domain and the management network domain are separate routing domains and the Interior Gateway Protocol instances are not redistributed or advertised to each other.'
  desc 'If the gateway router is not a dedicated device for the out-of-band management network, several safeguards must be implemented for containment of management and production traffic boundaries, otherwise, it is possible that management traffic will not be separated from production traffic. 

Since the managed network and the management network are separate routing domains, separate Interior Gateway Protocol routing instances must be configured on the router, one for the managed network and one for the out-of-band management network. In addition, the routes from the two domains must not be redistributed to each other.'
  desc 'check', 'Verify the Interior Gateway Protocol instance used for the managed network on the Cisco IOS XE router does not redistribute routes into the Interior Gateway Protocol instance used for the management network, and vice versa. The configuration will look similar to the example below:

router ospf 1
 area 1 authentication message-digest
 redistribute ospf 1 vrf Mgmt
 passive-interface default
 no passive-interface GigabitEthernet0/0
 no passive-interface GigabitEthernet0/1
 network 200.30.3.0 0.0.0.255 area 1

If the Interior Gateway Protocol instance used for the managed network redistributes routes into the Interior Gateway Protocol instance used for the management network, or vice versa, this is a finding.'
  desc 'fix', 'On the Cisco IOS XE router configure the Interior Gateway Protocol instance used for the managed network to prohibit redistribution of routes into the Interior Gateway Protocol instance used for the management network, and vice versa.

Use the “NO” form of the redistribute command to disable redistribution of the management network. For example:

ISR4000(config-router)#no redistribute ospf 1 vrf Mgmt'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74201r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74115'
  tag rid: 'SV-88789r2_rule'
  tag stig_id: 'CISR-RT-000010'
  tag gtitle: 'SRG-NET-000019-RTR-000013'
  tag fix_id: 'F-80657r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
