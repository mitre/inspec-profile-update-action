control 'SV-217031' do
  title 'The Juniper perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.'
  desc "Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic can be restricted directly by an access control list (ACL), which is a firewall function, or by Policy Routing. Policy Routing is a technique used to make routing decisions based on a number of different criteria other than just the destination network, including source or destination network, source or destination address, source or destination port, protocol, packet size, and packet classification. This overrides the router's normal routing procedures used to control the specific paths of network traffic. It is normally used for traffic engineering but can also be used to meet security requirements; for example, traffic that is not allowed can be routed to the Null0 or discard interface. Policy Routing can also be used to control which prefixes appear in the routing table.

This requirement is intended to allow network administrators the flexibility to use whatever technique is most effective."
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to determine if the router allows only incoming communications from authorized sources to be routed to authorized destinations. The hypothetical example below allows inbound NTP from host x.3.12.33 only to host x.1.22.4.

filter INBOUND_FILTER {
    term ALLOW_NTP {
        from {
            source-address {
                x.3.12.33/32;
            }
            destination-address {
                x.1.22.4/32;   <<< change to global address
            }
            protocol udp;
            destination-port ntp;
        }
    }
}

If the router does not restrict incoming communications to allow only authorized sources and destinations, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router to allow only incoming communications from authorized sources to be routed to authorized destinations.'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18260r296961_chk'
  tag severity: 'medium'
  tag gid: 'V-217031'
  tag rid: 'SV-217031r604135_rule'
  tag stig_id: 'JUNI-RT-000260'
  tag gtitle: 'SRG-NET-000364-RTR-000109'
  tag fix_id: 'F-18258r296962_fix'
  tag 'documentable'
  tag legacy: ['SV-101057', 'V-90847']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
