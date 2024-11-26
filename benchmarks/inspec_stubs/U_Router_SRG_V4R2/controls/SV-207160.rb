control 'SV-207160' do
  title 'The multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.'
  desc 'When a new source starts transmitting in a PIM Sparse Mode network, the DR will encapsulate the multicast packets into register messages and forward them to the RP using unicast. This process can be taxing on the CPU for both the DR and the RP if the source is running at a high data rate and there are many new sources starting at the same time. This scenario can potentially occur immediately after a network failover. The rate limit for the number of register messages should be set to a relatively low value based on the known number of multicast sources within the multicast domain.'
  desc 'check', 'Review the configuration of the RP to verify that it is rate limiting the number of multicast register messages.

If the RP is not limiting multicast register messages, this is a finding.'
  desc 'fix', 'Configure the RP to rate limit the number of multicast register messages.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7421r382508_chk'
  tag severity: 'medium'
  tag gid: 'V-207160'
  tag rid: 'SV-207160r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000121'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7421r382509_fix'
  tag 'documentable'
  tag legacy: ['V-78329', 'SV-93035']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
