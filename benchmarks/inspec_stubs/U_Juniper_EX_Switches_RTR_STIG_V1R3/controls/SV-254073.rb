control 'SV-254073' do
  title 'The Juniper perimeter router must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.'
  desc 'Many of the known attacks in stateless autoconfiguration are defined in RFC 3756 were present in IPv4 ARP attacks. To mitigate these vulnerabilities, links that have no hosts connected such as the interface connecting to external gateways must be configured to suppress router advertisements.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify Router Advertisements are suppressed on all external IPv6-enabled interfaces. By default, IPv6 router advertisements are disabled. Verify all configured interfaces are not external facing.
[edit protocols]
router-advertisement {
    interface <internal interface>.<logical unit> {
        managed-configuration;
        :
        :
        prefix <internal IPv6 prefix>;
    }
}

If the router is not configured to suppress Router Advertisements on all external IPv6-enabled interfaces, this is a finding.'
  desc 'fix', 'Configure the router to suppress Router Advertisements on all external IPv6-enabled interfaces.
If IPv6 router advertisements are not used, even for internal interfaces, delete or deactivate the [edit protocols router-advertisement] stanza.

[delete|deactivate] protocols router-advertisement

Delete or deactivate router advertisements on external interfaces.

[delete|deactivate] protocols router-advertisement interface <external interface>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57525r844250_chk'
  tag severity: 'medium'
  tag gid: 'V-254073'
  tag rid: 'SV-254073r844252_rule'
  tag stig_id: 'JUEX-RT-001010'
  tag gtitle: 'SRG-NET-000512-RTR-000014'
  tag fix_id: 'F-57476r844251_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
