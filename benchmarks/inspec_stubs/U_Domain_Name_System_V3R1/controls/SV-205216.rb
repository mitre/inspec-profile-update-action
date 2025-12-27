control 'SV-205216' do
  title 'The DNS server implementation must protect the integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

Confidentiality is not an objective of DNS, but integrity is. DNSSEC and TSIG/SIG(0) both digitally sign DNS information to authenticate its source and ensure its integrity.'
  desc 'check', 'Review the DNS implementation configuration to determine if the DNS server protects the integrity of transmitted information. If the DNS server does not protect the integrity of transmitted information, this is a finding.'
  desc 'fix', 'Configure the DNS server to protect the integrity of transmitted information.'
  impact 0.7
  ref 'DPMS Target DNS'
  tag check_id: 'C-5483r392561_chk'
  tag severity: 'high'
  tag gid: 'V-205216'
  tag rid: 'SV-205216r917686_rule'
  tag stig_id: 'SRG-APP-000439-DNS-000063'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-5483r392562_fix'
  tag 'documentable'
  tag legacy: ['SV-69137', 'V-54891']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
