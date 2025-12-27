control 'SV-207118' do
  title 'The multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated Router (DR) for any undesirable multicast groups and sources.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that register messages are accepted only for authorized multicast groups and sources.'
  desc 'check', 'Verify that the RP router is configured to filter PIM register messages. 

If the RP router peering with PIM-SM routers is not configured with a PIM import policy to block registration messages for any undesirable multicast groups and sources, this is a finding.'
  desc 'fix', 'Configure the RP router to filter PIM register messages received from a multicast DR for any undesirable multicast groups or sources.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7379r382247_chk'
  tag severity: 'low'
  tag gid: 'V-207118'
  tag rid: 'SV-207118r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000013'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7379r382248_fix'
  tag 'documentable'
  tag legacy: ['V-55747', 'SV-70001']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
