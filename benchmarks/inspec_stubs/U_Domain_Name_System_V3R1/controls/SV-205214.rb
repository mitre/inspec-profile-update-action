control 'SV-205214' do
  title 'The DNS server implementation must utilize cryptographic mechanisms to prevent unauthorized modification of DNS zone data.'
  desc 'Applications handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The DNS server must protect the integrity of keys (for TSIG/SIG(0) and DNSSEC) and DNS information.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server utilizes cryptographic mechanisms to prevent unauthorized modification of zone data. If the DNS server does not utilize cryptographic mechanisms to prevent unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the DNS server to utilize cryptographic mechanisms to prevent unauthorized modification of zone data.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5481r392555_chk'
  tag severity: 'medium'
  tag gid: 'V-205214'
  tag rid: 'SV-205214r879799_rule'
  tag stig_id: 'SRG-APP-000428-DNS-000061'
  tag gtitle: 'SRG-APP-000428'
  tag fix_id: 'F-5481r392556_fix'
  tag 'documentable'
  tag legacy: ['SV-69473', 'V-55227']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
