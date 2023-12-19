control 'SV-83239' do
  title 'The Windows 2008 DNS Server with a caching name server role must restrict recursive query responses to only the IP addresses and IP address ranges of known supported clients.'
  desc "A potential vulnerability of DNS is that an attacker can poison a name server's cache by sending queries that will cause the server to obtain host-to-IP address mappings from bogus name servers that respond with incorrect information. Once a name server has been poisoned, legitimate clients may be directed to non-existent hosts (which constitutes a denial of service), or, worse, hosts that masquerade as legitimate ones to obtain sensitive data or passwords.

To guard against poisoning, name servers specifically fulfilling the role of providing recursive query responses for external zones need to be segregated from name servers authoritative for internal zones."
  desc 'check', 'Note: If Windows DNS server is not serving in a caching role, this check is Not Applicable.
Verify the Windows DNS Server will only accept TCP and UDP port 53 traffic from specific IP addresses/ranges.

This can be configured via a local or network firewall.

If the caching name server is not restricted to answering queries from only specific networks, this is a finding.'
  desc 'fix', 'Configure a local or network firewall to only allow specific IP addresses/ranges to send inbound TCP and UDP port 53 traffic to a DNS caching server.'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59455r5_chk'
  tag severity: 'medium'
  tag gid: 'V-58583'
  tag rid: 'SV-83239r2_rule'
  tag stig_id: 'WDNS-CM-000005'
  tag gtitle: 'SRG-APP-000383-DNS-000047'
  tag fix_id: 'F-63967r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
