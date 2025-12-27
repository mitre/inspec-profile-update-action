control 'SV-207119' do
  title 'The multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Router (DR) for any undesirable multicast groups.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that join messages are only accepted for authorized multicast groups.'
  desc 'check', 'Verify that the RP router is configured to filter PIM register messages.

Note: Alternative is to configure all designated routers to filter IGMP Membership Report (a.k.a join) messages received from hosts.

If the RP router peering with PIM-SM routers is not configured with a PIM import policy to block registration messages for any undesirable multicast groups and Bogon sources, this is a finding.'
  desc 'fix', 'RP routers that are peering with customer PIM-SM routers must implement a PIM import policy to block join messages for reserved and any undesirable multicast groups.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7380r382250_chk'
  tag severity: 'low'
  tag gid: 'V-207119'
  tag rid: 'SV-207119r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000014'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7380r382251_fix'
  tag 'documentable'
  tag legacy: ['SV-70003', 'V-55749']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
