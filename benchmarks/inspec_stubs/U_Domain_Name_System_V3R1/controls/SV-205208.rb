control 'SV-205208' do
  title 'A DNS server implementation must provide additional integrity artifacts along with the authoritative name resolution data the system returns in response to external name/address resolution queries.'
  desc 'The major threat associated with DNS forged responses or failures is the integrity of the DNS data returned in the response. The principle of DNSSEC is to mitigate this threat by providing data origin authentication, establishing trust in the source. This requirement enables remote clients to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service. 

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS to map between host/service names and network addresses must provide other means to assure the authenticity and integrity of response data. 

In the case of DNS, employ DNSSEC to provide an additional data origin and integrity artifacts along with the authoritative data the system returns in response to DNS name/address resolution queries.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server provides additional integrity artifacts along with the authoritative name resolution data the system returns in response to external name/address resolution queries. If the DNS server does not provide such integrity artifacts, this is a finding.'
  desc 'fix', 'Configure the DNS server to provide additional integrity artifacts along with the authoritative name resolution data the system returns in response to external name/address resolution queries.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5475r392537_chk'
  tag severity: 'medium'
  tag gid: 'V-205208'
  tag rid: 'SV-205208r879793_rule'
  tag stig_id: 'SRG-APP-000422-DNS-000055'
  tag gtitle: 'SRG-APP-000422'
  tag fix_id: 'F-5475r392538_fix'
  tag 'documentable'
  tag legacy: ['SV-69117', 'V-54871']
  tag cci: ['CCI-002462']
  tag nist: ['SC-20 a']
end
