control 'SV-80865' do
  title 'Protocol Independent Multicast (PIM) join messages received from a downstream multicast Designated Routers (DR) must be filtered for any reserved or any other undesirable multicast groups.'
  desc 'Customer networks that do not maintain a multicast domain and only require the IP multicast service will be required to stand up a PIM-SM router that will be incorporated into the JIE shared tree structure by establishing a peering session with an RP router. Both of these implementations expose several risks that must be mitigated to provide a secure IP core network. All RP routers that are peering with customer PIM-SM routers must implement a PIM import policy to block multicast join requests for reserved or any other undesirable multicast groups.'
  desc 'check', 'Verify that the RP router is configured to filter PIM join messages for any reserved multicast groups using the ip pim accept-rp global command as shown in the example below. The ip pim accept-rp global command causes the router to accept only (*, G) join messages destined for the specified RP address as allowed by the referenced access-list.

ip pim accept-rp 10.10.2.1 PIM_JOIN_FILTER
!
ip access-list standard PIM_JOIN_FILTER
deny 224.0.1.2
deny 224.0.1.3
deny 224.0.1.8
deny 224.0.1.22
deny 224.0.1.24
deny 224.0.1.25
...
...
...
deny 225.1.2.3
deny 229.55.150.208
deny 234.42.42.42 255.255.255.252
deny 239.0.0.0 0.255.255.255
permit any

Note: IOS 12.4T extends the ip multicast-routing command with a group-range or access-list argument that can be used to filter multicast control (PIM, IGMP) and data packets for unauthorized groups. 

If the RP router peering with customer PIM-SM routers is not configured with a PIM import policy to block join messages for reserved and any undesirable multicast groups, this is a finding.'
  desc 'fix', 'RP routers that are peering with customer PIM-SM routers must implement a PIM import policy to block join messages for reserved and any undesirable multicast groups.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-67023r1_chk'
  tag severity: 'low'
  tag gid: 'V-66375'
  tag rid: 'SV-80865r1_rule'
  tag stig_id: 'NET2011'
  tag gtitle: 'NET2011'
  tag fix_id: 'F-72451r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
