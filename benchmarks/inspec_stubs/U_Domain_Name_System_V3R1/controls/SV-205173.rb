control 'SV-205173' do
  title 'Only the private key corresponding to the ZSK alone must be kept on the name server that does support dynamic updates.'
  desc 'The private keys in the KSK and ZSK key pairs must be protected from unauthorized access. If possible, the private keys should be stored off-line (with respect to the Internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy. 

This strategy is not feasible in situations in which the DNSSEC-aware name server has to support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) has to have both the zone file master copy and the private key corresponding to the zone-signing key (ZSK-private) online to immediately update the signatures for the updated RRsets. The private key corresponding to the key-signing key (KSK-private) can still be kept off-line.'
  desc 'check', 'Review the DNS name server and documentation to determine whether it accepts dynamic updates. If dynamic updates are accepted, verify only the private keys corresponding to the ZSK (Zone Signing Key) are located on the server.

If the private keys to the KSK are located on the name server that accepts dynamic updates, this is a finding.'
  desc 'fix', 'Store the private keys of the ZSK and KSK off-line in an encrypted file system.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5440r392435_chk'
  tag severity: 'medium'
  tag gid: 'V-205173'
  tag rid: 'SV-205173r879613_rule'
  tag stig_id: 'SRG-APP-000176-DNS-000094'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-5440r392436_fix'
  tag 'documentable'
  tag legacy: ['SV-69055', 'V-54809']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
