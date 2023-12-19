control 'SV-205212' do
  title 'A DNS server implementation must perform data origin verification authentication on the name/address resolution responses the system receives from authoritative sources.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed which would result in query failure or denial of service. Data origin authentication verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching DNS servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations."
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server performs data origin verification authentication on the name/address resolution responses the system receives from authoritative sources. If the DNS server does not perform data origin verification authentication on the responses, this is a finding.'
  desc 'fix', 'Configure the DNS server to perform data origin verification authentication on the name/address resolution responses the system receives from authoritative sources.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5479r392549_chk'
  tag severity: 'medium'
  tag gid: 'V-205212'
  tag rid: 'SV-205212r879797_rule'
  tag stig_id: 'SRG-APP-000426-DNS-000059'
  tag gtitle: 'SRG-APP-000426'
  tag fix_id: 'F-5479r392550_fix'
  tag 'documentable'
  tag legacy: ['SV-69131', 'V-54885']
  tag cci: ['CCI-002468']
  tag nist: ['SC-21']
end
