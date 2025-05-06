control 'SV-215607' do
  title 'The private key corresponding to the ZSK must only be stored on the name server that does support dynamic updates.'
  desc 'The private keys in the KSK and ZSK key pairs must be protected from unauthorized access. If possible, the private keys should be stored off-line (with respect to the Internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy.

This strategy is not feasible in situations in which the DNSSEC-aware name server has to support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) has to have both the zone file master copy and the private key corresponding to the zone-signing key (ZSK-private) online to immediately update the signatures for the updated RRsets. The private key corresponding to the key-signing key (KSK-private) can still be kept off-line.'
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

Note: This requirement is not applicable to servers with only a caching role.

For Active Directory-integrated zones, private zone signing keys replicate automatically to all primary DNS servers through Active Directory replication. Each authoritative server signs its own copy of the zone when it receives the key. For optimal performance, and to prevent increasing the size of the Active Directory database file, the signed copy of the zone remains in memory for Active Directory-integrated zones. A DNSSEC-signed zone is only committed to disk for file-backed zones. Secondary DNS servers pull a full copy of the zone, including signatures, from the primary DNS server.

If all DNS servers are AD integrated, this check is not applicable.

If a DNS server is not AD integrated and has file-backed zones, does not accept dynamic updates and has a copy of the private key corresponding to the ZSK, this is a finding.'
  desc 'fix', 'Ensure the private key corresponding to the ZSK is only stored on the name server accepting dynamic updates.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16801r572384_chk'
  tag severity: 'medium'
  tag gid: 'V-215607'
  tag rid: 'SV-215607r561297_rule'
  tag stig_id: 'WDNS-IA-000009'
  tag gtitle: 'SRG-APP-000176-DNS-000094'
  tag fix_id: 'F-16799r314297_fix'
  tag 'documentable'
  tag legacy: ['SV-73077', 'V-58647']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
