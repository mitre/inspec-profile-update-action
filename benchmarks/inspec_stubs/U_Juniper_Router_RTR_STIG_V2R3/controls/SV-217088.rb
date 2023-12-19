control 'SV-217088' do
  title 'The Juniper multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.'
  desc 'When a new source starts transmitting in a PIM Sparse Mode network, the DR will encapsulate the multicast packets into register messages and forward them to the RP using unicast. This process can be taxing on the CPU for both the DR and the RP if the source is running at a high data rate and there are many new sources starting at the same time. This scenario can potentially occur immediately after a network failover. The rate limit for the number of register messages should be set to a relatively low value based on the known number of multicast sources within the multicast domain.'
  desc 'check', 'Review the configuration of the RP to verify that it is rate limiting the number of multicast register messages.

protocols {
    …
    …
    …
    }
    pim {
        rp {
            register-limit maximum nnnnn;
            local {
                address 2.2.2.2;
            }
        }

Note: Each any-source group (*,G) counts as one group toward the limit. Each source-specific group (S,G) counts as one group toward the limit.

If the RP is not limiting multicast register messages, this is a finding.'
  desc 'fix', 'Configure the RP to rate limit the number of multicast register messages it will allow for each (S, G) entry.

[edit protocols pim rp]
set register-limit maximum nnnnn'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18317r297132_chk'
  tag severity: 'medium'
  tag gid: 'V-217088'
  tag rid: 'SV-217088r604135_rule'
  tag stig_id: 'JUNI-RT-000840'
  tag gtitle: 'SRG-NET-000362-RTR-000121'
  tag fix_id: 'F-18315r297133_fix'
  tag 'documentable'
  tag legacy: ['SV-101169', 'V-90959']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
