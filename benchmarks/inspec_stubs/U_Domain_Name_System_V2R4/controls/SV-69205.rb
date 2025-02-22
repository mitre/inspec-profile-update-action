control 'SV-69205' do
  title 'The private key corresponding to the ZSK, stored on name servers accepting dynamic updates, must have appropriate directory/file-level access control list-based or cryptography-based protections.'
  desc 'The private keys in the KSK and ZSK key pairs must be protected from unauthorized access. If possible, the private keys should be stored off-line (with respect to the Internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy. 

This strategy is not feasible in situations in which the DNSSEC-aware name server has to support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) has to have both the zone file master copy and the private key corresponding to the zone-signing key (ZSK-private) online to immediately update the signatures for the updated RRsets. The private key corresponding to the key-signing key (KSK-private) can still be kept off-line.'
  desc 'check', 'Review the DNS name server and documentation to determine whether it accepts dynamic updates. If dynamic updates are accepted, ensure the private key corresponding to the ZSK alone is protected with directory/file-level access control list-based or cryptography-based protections.

If the private key corresponding to the ZSK alone is not protected with directory/file-level access control list-based or cryptography-based protections, this is a finding.'
  desc 'fix', 'Apply permissions to the private key corresponding to the ZSK alone with read/modify permissions for the account under which the name server software is run.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55585r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54959'
  tag rid: 'SV-69205r1_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000111'
  tag gtitle: 'SRG-APP-000516-DNS-000111'
  tag fix_id: 'F-59821r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
