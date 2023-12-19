control 'SV-205234' do
  title 'An authoritative name server must be configured to enable DNSSEC Resource Records.'
  desc "The specification for a digital signature mechanism in the context of the DNS infrastructure is in IETF's DNSSEC standard.  In DNSSEC, trust in the public key (for signature verification) of the source is established not by going to a third party or a chain of third parties (as in public key infrastructure [PKI] chaining), but by starting from a trusted zone (such as the root zone) and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. The public key of the trusted zone is called the trust anchor. After authenticating the source, the next process DNSSEC calls for is to authenticate the response. DNSSEC mechanisms involve two main processes: sign and serve, and verify signature.

Before a DNSSEC-signed zone can be deployed, a name server must be configured to enable DNSSEC processing."
  desc 'check', 'Check the DNS configuration to ensure DNSSEC Resource Records has been enabled.

If the name server is not configured with DNSSEC enabled, this is a finding.'
  desc 'fix', 'Configure the name server with DNSSEC enabled.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5501r392615_chk'
  tag severity: 'medium'
  tag gid: 'V-205234'
  tag rid: 'SV-205234r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000089'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5501r392616_fix'
  tag 'documentable'
  tag legacy: ['SV-69177', 'V-54931']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
