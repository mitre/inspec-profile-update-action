control 'SV-205207' do
  title 'A DNS server implementation must provide data integrity protection artifacts for internal name/address resolution queries.'
  desc 'The major threat associated with DNS forged responses or failures is the integrity of the DNS data returned in the response. The principle of DNSSEC is to mitigate this threat by providing data origin authentication, establishing trust in the source. This requirement enables remote clients to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service. 

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS to map between host/service names and network addresses must provide other means to assure the authenticity and integrity of response data. 

In the case of DNS, employ DNSSEC to provide an additional data origin and integrity artifacts along with the authoritative data the system returns in response to DNS name/address resolution queries.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server provides data integrity protection artifacts for internal name/address resolution queries. If the DNS server does not provide these artifacts, this is a finding.'
  desc 'fix', 'Configure the DNS server to provide data integrity protection artifacts for internal name/address resolution queries.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5474r392534_chk'
  tag severity: 'medium'
  tag gid: 'V-205207'
  tag rid: 'SV-205207r879792_rule'
  tag stig_id: 'SRG-APP-000421-DNS-000054'
  tag gtitle: 'SRG-APP-000421'
  tag fix_id: 'F-5474r392535_fix'
  tag 'documentable'
  tag legacy: ['SV-69115', 'V-54869']
  tag cci: ['CCI-002464', 'CCI-000366']
  tag nist: ['SC-20 (2)', 'CM-6 b']
end
