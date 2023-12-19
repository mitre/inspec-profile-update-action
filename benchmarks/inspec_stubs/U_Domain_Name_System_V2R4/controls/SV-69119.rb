control 'SV-69119' do
  title 'A DNS server implementation must request data origin authentication verification on the name/address resolution responses the system receives from authoritative sources.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed that would result in query failure or denial of service. Data origin authentication must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching DNS servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations."
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server requests data origin authentication verification on the name/address resolution responses the system receives from authoritative sources. If the DNS server does not request data origin authentication verification on the responses, this is a finding.'
  desc 'fix', 'Configure the DNS server to request data origin authentication verification on the name/address resolution responses the system receives from authoritative sources.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55497r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54873'
  tag rid: 'SV-69119r1_rule'
  tag stig_id: 'SRG-APP-000423-DNS-000056'
  tag gtitle: 'SRG-APP-000423-DNS-000056'
  tag fix_id: 'F-59731r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002465']
  tag nist: ['SC-21']
end
