control 'SV-205198' do
  title 'The DNS server implementation must validate the binding of the other DNS servers identity to the DNS information for a server-to-server transaction (e.g., zone transfer).'
  desc "Validation of the binding of the information prevents the modification of information between production and review. The validation of bindings can be achieved, for example, by the use of cryptographic checksums. Validations must be performed automatically.

DNSSEC and TSIG/SIG(0) technologies are not effective unless the digital signatures they generate are validated to ensure that the information has not been tampered with and that the producer's identity is legitimate."
  desc 'check', "Review the DNS server implementation configuration to determine if the DNS server validates the binding of the other DNS server's identity to the DNS information for a server-to-server transaction (e.g., zone transfer). If the DNS server does not validate the binding of the other DNS server's identity to the DNS information, this is a finding."
  desc 'fix', "Configure the DNS server to validate the binding of the other DNS server's identity to the DNS information for a server-to-server transaction (e.g., zone transfer)."
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5465r392507_chk'
  tag severity: 'medium'
  tag gid: 'V-205198'
  tag rid: 'SV-205198r879726_rule'
  tag stig_id: 'SRG-APP-000349-DNS-000043'
  tag gtitle: 'SRG-APP-000349'
  tag fix_id: 'F-5465r392508_fix'
  tag 'documentable'
  tag legacy: ['SV-69221', 'V-54975']
  tag cci: ['CCI-001904', 'CCI-000366']
  tag nist: ['AU-10 (2) (a)', 'CM-6 b']
end
