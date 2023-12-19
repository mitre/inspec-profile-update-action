control 'WDNS-22-000107_rule' do
  title 'The private keys corresponding to both the zone signing key (ZSK) and the key signing key (KSK) must not be kept on the DNSSEC-aware primary authoritative name server when the name server does not support dynamic updates.'
  desc 'The private keys in the KSK and ZSK key pairs must be protected from unauthorized access. If possible, the private keys should be stored offline (with respect to the internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy.

This strategy is not feasible in situations in which the DNSSEC-aware name server must support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) must have both the zone file master copy and the private key corresponding to the zone signing key (ZSK-private) online to immediately update the signatures for the updated Resource Record Sets. The private key corresponding to the key signing key (KSK-private) can still be kept offline.'
  desc 'check', 'Review the DNS name server and documentation to determine if it accepts dynamic updates. 

If dynamic updates are not accepted, verify the private keys corresponding to both the ZSK and KSK are not located on the name server.

If the private keys to the ZSK and/or the KSK are located on the name server, this is a finding.'
  desc 'fix', 'Store the private keys of the ZSK and KSK offline in an encrypted file system.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000107_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000107'
  tag rid: 'WDNS-22-000107_rule'
  tag stig_id: 'WDNS-22-000107'
  tag gtitle: 'SRG-APP-000516-DNS-000112'
  tag fix_id: 'F-WDNS-22-000107_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
