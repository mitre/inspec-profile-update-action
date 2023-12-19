control 'SV-80863' do
  title 'Protocol Independent Multicast (PIM) register messages received from a downstream multicast Designated Routers (DR) must be filtered for any reserved or any other undesirable multicast groups.'
  desc 'Customer networks that do not maintain a multicast domain and only require the IP multicast service will be required to stand up a PIM-SM router that will be incorporated into the JIE shared tree structure by establishing a peering session with an RP router. Both of these implementations expose several risks that must be mitigated to provide a secured IP core network. All RP routers that are peering with customer PIM-SM routers must implement a PIM import policy to block multicast registration requests for reserved or any other undesirable multicast groups.'
  desc 'check', 'Verify that the RP router is configured to filter PIM register messages using the ip pim accept-register global command as shown in the example below. This command can reference either an ACL or a route-map to identify and prevent unauthorized sources or groups from registering with the RP.

ip pim accept-register list PIM_REGISTER_FILTER
!
ip access-list extended PIM_REGISTER_FILTER
deny  ip any 224.0.0.0 0.0.0.255
deny  ip 0.0.0.0 0.255.255.255 any
deny  ip 1.0.0.0 0.255.255.255 any
deny  ip 2.0.0.0 0.255.255.255 any
deny  ip 5.0.0.0 0.255.255.255 any
deny  ip 7.0.0.0 0.255.255.255 any
deny  ip 10.0.0.0 0.255.255.255 any
deny  ip 23.0.0.0 0.255.255.255 any
deny  ip 27.0.0.0 0.255.255.255 any
...
...
...
deny  ip 172.16.0.0 0.15.255.255 any
deny  ip 192.168.0.0 0.0.255.255 any
deny  ip 197.0.0.0 0.255.255.255 any
deny  ip 223.0.0.0 0.255.255.255 any
deny  ip 224.0.0.0 224.255.255.255 any
permit ip any any

If the RP router peering with customer PIM-SM routers is not configured with a PIM import policy to block registration messages for reserved multicast groups, this is a finding.'
  desc 'fix', 'Configure RP routers to filter PIM register messages received from a tenant multicast DR for any reserved or any other undesirable multicast groups.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-67019r1_chk'
  tag severity: 'low'
  tag gid: 'V-66373'
  tag rid: 'SV-80863r1_rule'
  tag stig_id: 'NET2010'
  tag gtitle: 'NET2010'
  tag fix_id: 'F-72449r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
