control 'SV-215576' do
  title 'The Windows 2012 DNS Server with a caching name server role must be secured against pollution by ensuring the authenticity and integrity of queried records.'
  desc "A potential vulnerability of DNS is that an attacker can poison a name server's cache by sending queries that will cause the server to obtain host-to-IP address mappings from bogus name servers that respond with incorrect information. Once a name server has been poisoned, legitimate clients may be directed to non-existent hosts (which constitutes a denial of service), or, worse, hosts that masquerade as legitimate ones to obtain sensitive data or passwords.

To guard against poisoning, name servers authoritative for .mil domains should be separated functionally from name servers that resolve queries on behalf of internal clients. Organizations may achieve this separation by dedicating machines to each function or, if possible, by running two instances of the name server software on the same machine: one for the authoritative function and the other for the resolving function. In this design, each name server process may be bound to a different IP address or network interface to implement the required segregation.

Windows 2012 DNS Servers with a caching name server role must be secured against pollution by ensuring that the authenticity and integrity of queried records are verified before any data is cached."
  desc 'check', "Note: Blackhole name servers host records which are manually added and for which the name server is not authoritative. It is configured and intended to block resolvers from getting to a destination by directing the query to a blackhole. If the blackhole name server is not authoritative for any zones and otherwise only serves as a caching/forwarding name server, this check is Not Applicable.

The non-AD-integrated, standalone, caching Windows 2012 DNS Server must be configured to be DNSSEC-aware. When performing caching and lookups, the caching name server must be able to obtain a zone signing key DNSKEY record and corresponding RRSIG record for the queried record. It will use this information to compute the hash for the hostname being resolved. The caching name server decrypts the RRSIG record for the hostname being resolved with the zone's ZSK to get the RRSIG record hash. The caching name server compares the hashes and ensures they match.

If the non-AD-integrated, standalone, caching Windows 2012 DNS Server is not configured to be DNSSEC-aware, this is a finding."
  desc 'fix', 'Implement DNSSEC on all non-AD-integrated, standalone, caching Windows 2012 DNS Servers to ensure caching server validates signed zones when resolving and caching.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16770r572197_chk'
  tag severity: 'medium'
  tag gid: 'V-215576'
  tag rid: 'SV-215576r561297_rule'
  tag stig_id: 'WDNS-CM-000006'
  tag gtitle: 'SRG-APP-000383-DNS-000047'
  tag fix_id: 'F-16768r572198_fix'
  tag 'documentable'
  tag legacy: ['SV-73015', 'V-58585']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
