control 'SV-207571' do
  title 'The BIND 9.x server private key corresponding to the ZSK pair must be the only DNSSEC key kept on a name server that supports dynamic updates.'
  desc 'The private key in the ZSK key pair must be protected from unauthorized access. If possible, the private key should be stored off-line (with respect to the Internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy. 

This strategy is not feasible in situations in which the DNSSEC-aware name server has to support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) has to have both the zone file master copy and the private key corresponding to the zone-signing key (ZSK-private) online to immediately update the signatures for the updated RRsets.

Failure to protect the private ZSK opens it to being maliciously obtained and opens the DNS zone to being populated with invalid data. The integrity of the DNS zone would be compromised leading to a loss of trust whether a DNS response has originated from an authentic source, the response is complete, and has not been tampered with during transit.'
  desc 'check', 'If the server is in a classified network, this is Not Applicable.

Determine if the BIND 9.x server is configured to allow dynamic updates.

Review the "named.conf" file for any instance of the "allow-update" statement. The following example disables dynamic updates:

allow-update {none;};

If the BIND 9.x implementation is not configured to allow dynamic updates, verify with the SA that the ZSK private key is stored offline. If it is not, this is a finding.

If the BIND 9.x implementation is configured to allow dynamic updates, verify that the ZSK private key is the only key stored on the name server.

For each signed zone file, identify the ZSK "key id" number:

# cat <signed_zone_file> | grep -i "zsk"
ZSK; alg = ECDSAP256SHA256; key id = 22335

Using the ZSK "key id", verify that the only private key stored on the system matches the "key id"

Kexample.com.+008+22335.private

If any ZSK private keys exist on the server other than the one corresponding to the active ZSK pair, this is a finding.'
  desc 'fix', 'Remove any ZSK private keys existing on the server other than the one corresponding to the active ZSK pair'
  impact 0.7
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7826r283767_chk'
  tag severity: 'high'
  tag gid: 'V-207571'
  tag rid: 'SV-207571r612253_rule'
  tag stig_id: 'BIND-9X-001133'
  tag gtitle: 'SRG-APP-000176-DNS-000094'
  tag fix_id: 'F-7826r283768_fix'
  tag 'documentable'
  tag legacy: ['SV-87077', 'V-72453']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
