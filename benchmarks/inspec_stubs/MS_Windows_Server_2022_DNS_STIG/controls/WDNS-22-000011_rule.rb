control 'WDNS-22-000011_rule' do
  title 'The Windows 2022 DNS Server with a caching name server role must restrict recursive query responses to only the IP addresses and IP address ranges of known supported clients.'
  desc "A potential vulnerability of DNS is that an attacker can poison a name server's cache by sending queries that will cause the server to obtain host-to-IP address mappings from bogus name servers that respond with incorrect information. Once a name server has been poisoned, legitimate clients may be directed to nonexistent hosts (which constitutes a denial of service) or hosts that masquerade as legitimate ones to obtain sensitive data or passwords.

To guard against poisoning, name servers specifically fulfilling the role of providing recursive query responses for external zones must be segregated from name servers authoritative for internal zones."
  desc 'check', "Note: Sinkhole name servers host records that are manually added and for which the name server is not authoritative. It is configured and intended to block resolvers from reaching a destination by directing the query to a sinkhole. If the sinkhole name server is not authoritative for any zones and serves only as a caching/forwarding name server, this check is not applicable.

The non-Active Directory (AD)-integrated, standalone, caching Windows 2022 DNS Server must be configured to be DNSSEC aware. When performing caching and lookups, the caching name server must be able to obtain a zone signing key (ZSK) DNSKEY record and corresponding RRSIG record for the queried record. It will use this information to compute the hash for the hostname being resolved. The caching name server decrypts the RRSIG record for the hostname being resolved with the zone's ZSK to get the RRSIG record hash. The caching name server compares the hashes and ensures they match.

If the non-AD-integrated, standalone, caching Windows 2022 DNS Server is not configured to be DNSSEC aware, this is a finding."
  desc 'fix', 'Implement DNSSEC on all non-AD-integrated, standalone, caching Windows 2022 DNS Servers to ensure the caching server validates signed zones when resolving and caching.'
  impact 0.7
  tag check_id: 'C-WDNS-22-000011_chk'
  tag severity: 'high'
  tag gid: 'WDNS-22-000011'
  tag rid: 'WDNS-22-000011_rule'
  tag stig_id: 'WDNS-22-000011'
  tag gtitle: 'SRG-APP-000383-DNS-000047'
  tag fix_id: 'F-WDNS-22-000011_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
