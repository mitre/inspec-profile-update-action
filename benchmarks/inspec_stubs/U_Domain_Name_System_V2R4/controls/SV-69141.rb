control 'SV-69141' do
  title 'The DNS server implementation must implement cryptographic mechanisms to detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).'
  desc 'Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes. 

Confidentiality is not an objective of DNS, but integrity is. DNSSEC and TSIG/SIG(0) both digitally sign DNS information to authenticate its source and ensure its integrity.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server implements cryptographic mechanisms to detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS). If the DNS server does not implement such cryptographic mechanisms, this is a finding.'
  desc 'fix', 'Configure the DNS server to detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution Systems (PDS).'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55521r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54895'
  tag rid: 'SV-69141r1_rule'
  tag stig_id: 'SRG-APP-000440-DNS-000065'
  tag gtitle: 'SRG-APP-000440-DNS-000065'
  tag fix_id: 'F-59757r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
