control 'SV-69047' do
  title 'The DNS server implementation, when using PKI-based authentication, must enforce authorized access to the corresponding private key.'
  desc 'The cornerstone of the PKI is the private key used to encrypt or digitally sign information. If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user. Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys. 

SIG(0) is used for server-to-server authentication for DNS transactions, and it uses PKI-based authentication. So, in cases where SIG(0) is being used instead of TSIG (which uses a shared key, not PKI-based authentication), this requirement is applicable.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server, when using PKI-based authentication (e.g., SIG(0)), enforces authorized access to the corresponding private key. If the DNS server does not enforce authorized access to the private key, this is a finding.'
  desc 'fix', 'Configure the DNS server to enforce authorized access to the corresponding private key when using PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55423r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54801'
  tag rid: 'SV-69047r1_rule'
  tag stig_id: 'SRG-APP-000176-DNS-000017'
  tag gtitle: 'SRG-APP-000176-DNS-000017'
  tag fix_id: 'F-59659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
