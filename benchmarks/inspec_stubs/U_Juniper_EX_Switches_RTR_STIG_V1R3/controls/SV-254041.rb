control 'SV-254041' do
  title 'The Juniper multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.'
  desc 'When a new source starts transmitting in a PIM Sparse Mode network, the DR will encapsulate the multicast packets into register messages and forward them to the RP using unicast. This process can be taxing on the CPU for both the DR and the RP if the source is running at a high data rate and there are many new sources starting at the same time. This scenario can potentially occur immediately after a network failover. The rate limit for the number of register messages should be set to a relatively low value based on the known number of multicast sources within the multicast domain.'
  desc 'check', 'Review the configuration of the RP to verify that it is rate limiting the number of multicast register messages.

[edit protocols pim]
rp {
    register-limit {
        maximum <1..65535>;
    }
    <additional configuration>
}

If the RP is not limiting multicast register messages, this is a finding.'
  desc 'fix', 'Configure the RP to rate limit the number of multicast register messages.

set protocols pim rp register-limit maximum <1..65535>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57493r844154_chk'
  tag severity: 'medium'
  tag gid: 'V-254041'
  tag rid: 'SV-254041r844156_rule'
  tag stig_id: 'JUEX-RT-000690'
  tag gtitle: 'SRG-NET-000362-RTR-000121'
  tag fix_id: 'F-57444r844155_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
