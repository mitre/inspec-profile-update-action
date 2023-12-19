control 'SV-205215' do
  title 'The DNS server implementation must utilize cryptographic mechanisms to prevent unauthorized disclosure of non-DNS data stored on the DNS server.'
  desc 'Applications handling data requiring "data-at-rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the confidentiality of organizational information. The strength of mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The DNS server must protect the confidentiality of keys (for TSIG/SIG(0) and DNSSEC). There is no need to protect the confidentiality of DNS information because it is accessible by all devices that can contact the server.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server utilizes cryptographic mechanisms to prevent unauthorized disclosure of non-DNS data while stored on the DNS server. 

If the DNS server does not utilize cryptographic mechanisms to prevent unauthorized disclosure, this is a finding.'
  desc 'fix', 'Configure the DNS server to utilize cryptographic mechanisms to prevent unauthorized disclosure of non-DNS data while stored on the DNS server.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5482r392558_chk'
  tag severity: 'medium'
  tag gid: 'V-205215'
  tag rid: 'SV-205215r879800_rule'
  tag stig_id: 'SRG-APP-000429-DNS-000062'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-5482r392559_fix'
  tag 'documentable'
  tag legacy: ['SV-69135', 'V-54889']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
