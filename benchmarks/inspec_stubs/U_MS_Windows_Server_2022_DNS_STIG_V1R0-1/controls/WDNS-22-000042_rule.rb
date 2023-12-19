control 'WDNS-22-000042_rule' do
  title 'The private key corresponding to the zone signing key (ZSK) must only be stored on the name server that does support dynamic updates.'
  desc 'The private keys in the key signing key (KSK) and ZSK key pairs must be protected from unauthorized access. If possible, the private keys should be stored offline (with respect to the internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file primary copy.

This strategy is not feasible in situations in which the DNSSEC-aware name server must support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) must have both the zone file master copy and the private key corresponding to the zone signing key (ZSK-private) online to immediately update the signatures for the updated resource record (RR) sets. The private key corresponding to the key signing key (KSK-private) can still be kept offline.'
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory (AD)-integrated zones or for Windows 2022 DNS Servers on a classified network.

Note: This requirement is not applicable to servers with only a caching role.

For AD-integrated zones, private zone signing keys replicate automatically to all primary DNS servers through AD replication. Each authoritative server signs its own copy of the zone when it receives the key. For optimal performance, and to prevent increasing the size of the AD database file, the signed copy of the zone remains in memory for AD-integrated zones. A DNSSEC-signed zone is only committed to disk for file-backed zones. Secondary DNS servers pull a full copy of the zone, including signatures, from the primary DNS server.

If all DNS servers are AD integrated, this check is not applicable.

If a DNS server is not AD integrated and has file-backed zones, does not accept dynamic updates, and has a copy of the private key corresponding to the ZSK, this is a finding.'
  desc 'fix', 'Ensure the private key corresponding to the ZSK is only stored on the name server accepting dynamic updates.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000042_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000042'
  tag rid: 'WDNS-22-000042_rule'
  tag stig_id: 'WDNS-22-000042'
  tag gtitle: 'SRG-APP-000176-DNS-000094'
  tag fix_id: 'F-WDNS-22-000042_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
