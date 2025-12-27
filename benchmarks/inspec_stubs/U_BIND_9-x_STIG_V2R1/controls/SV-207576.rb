control 'SV-207576' do
  title 'The BIND 9.x server signature generation using the KSK must be done off-line, using the KSK-private key stored off-line.'
  desc 'The private key in the KSK key pair must be protected from unauthorized access. The private key should be stored off-line (with respect to the Internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy. 

Failure to protect the private KSK may have significant effects on the overall security of the DNS infrastructure. A compromised KSK could lead to an inability to detect unauthorized DNS zone data resulting in network traffic being redirected to a rogue site.'
  desc 'check', 'If the server is in a classified network, this is Not Applicable.

Ensure that there are no private KSKs stored on the name sever. 

With the assistance of the DNS Administrator, obtain a list of all DNSSEC private keys that are stored on the name server. 

Inspect the signed zone files(s) and look for the KSK key id:

DNSKEY 257 3 8 ( <hash_algorithm) ; KSK ; alg = ECDSAP256SHA256; key id = 52807

Verify that none of the identified private keys, are KSKs.

An example private KSK would look like the following:

Kexample.com.+008+52807.private

If there are private KSKs stored on the name server, this is a finding.'
  desc 'fix', 'Remove all private KSKs from the name server and ensure that they are stored offline in a secure location.'
  impact 0.7
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7831r283782_chk'
  tag severity: 'high'
  tag gid: 'V-207576'
  tag rid: 'SV-207576r612253_rule'
  tag stig_id: 'BIND-9X-001150'
  tag gtitle: 'SRG-APP-000176-DNS-000096'
  tag fix_id: 'F-7831r283783_fix'
  tag 'documentable'
  tag legacy: ['SV-87093', 'V-72469']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
