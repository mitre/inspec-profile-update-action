control 'SV-233292' do
  title 'The Juniper perimeter router must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.'
  desc 'Many of the known attacks in stateless autoconfiguration are defined in RFC 3756 were present in IPv4 ARP attacks. To mitigate these vulnerabilities, links that have no hosts connected such as the interface connecting to external gateways must be configured to suppress router advertisements.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify that Router Advertisements are suppressed on all external IPv6-enabled interfaces as shown in the example below.

By default, router advertisements are disabled by Junos. Verify that there are no external-facing interfaces defined under the protocols router-advertisement hierarchy as shown in the example below.

protocols {
    router-advertisement {
        interface fe-0/1/0.0 {
            prefix 2001:1:123::/64;
        }
    }
}

If the router is not configured to suppress Router Advertisements on all external IPv6-enabled interfaces, this is a finding.'
  desc 'fix', 'Remove any external IPv6-enabled interfaces from the protocols router-advertisement hierarchy.'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-36228r639641_chk'
  tag severity: 'medium'
  tag gid: 'V-233292'
  tag rid: 'SV-233292r604135_rule'
  tag stig_id: 'JUNI-RT-000381'
  tag gtitle: 'SRG-NET-000512-RTR-000014'
  tag fix_id: 'F-36196r622159_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
