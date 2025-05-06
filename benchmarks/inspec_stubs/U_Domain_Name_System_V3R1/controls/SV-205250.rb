control 'SV-205250' do
  title 'The private keys corresponding to both the ZSK and the KSK must not be kept on the DNSSEC-aware primary authoritative name server when the name server does not support dynamic updates.'
  desc 'The private keys in the KSK and ZSK key pairs must be protected from unauthorized access. If possible, the private keys should be stored off-line (with respect to the Internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy. 

This strategy is not feasible in situations in which the DNSSEC-aware name server has to support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) has to have both the zone file master copy and the private key corresponding to the zone-signing key (ZSK-private) online to immediately update the signatures for the updated RRsets. The private key corresponding to the key-signing key (KSK-private) can still be kept off-line.'
  desc 'check', 'Review the DNS name server and documentation to determine whether it accepts dynamic updates. If dynamic updates are not accepted, verify the private keys corresponding to both the ZSK (Zone Signing Key) and KSK (Key Signing Key) are not located on the name server.

If the private keys to the ZSK and/or the KSK are located on the name server, this is a finding.'
  desc 'fix', 'Store the private keys of the ZSK and KSK off-line in an encrypted file system.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5517r392663_chk'
  tag severity: 'medium'
  tag gid: 'V-205250'
  tag rid: 'SV-205250r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000112'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5517r392664_fix'
  tag 'documentable'
  tag legacy: ['SV-69207', 'V-54961']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
