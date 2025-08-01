control 'SV-214206' do
  title 'An authoritative name server must be configured to enable DNSSEC Resource Records.'
  desc "The specification for a digital signature mechanism in the context of the DNS infrastructure is in IETF's DNSSEC standard. In DNSSEC, trust in the public key (for signature verification) of the source is established not by going to a third party or a chain of third parties (as in public key infrastructure [PKI] chaining), but by starting from a trusted zone (such as the root zone) and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. The public key of the trusted zone is called the trust anchor. After authenticating the source, the next process DNSSEC calls for is to authenticate the response. DNSSEC mechanisms involve two main processes: sign and serve, and verify signature.

Before a DNSSEC-signed zone can be deployed, a name server must be configured to enable DNSSEC processing."
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Validate that DNSSEC is enabled by navigating to Data Management >> DNS >> Grid DNS properties.

Toggle Advanced Mode click on "DNSSEC" tab.
When complete, click "Cancel" to exit the "Properties" screen.

If "Enable DNSSEC" is not configured this is a finding.'
  desc 'fix', 'DNSSEC must be enabled prior to zone signing. Enable by navigating to Data Management >> DNS >> Grid DNS properties.

Toggle Advanced Mode click on "DNSSEC" tab. Enable the "Enable DNSSEC" option.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15421r295881_chk'
  tag severity: 'medium'
  tag gid: 'V-214206'
  tag rid: 'SV-214206r612370_rule'
  tag stig_id: 'IDNS-7X-000770'
  tag gtitle: 'SRG-APP-000516-DNS-000089'
  tag fix_id: 'F-15419r295882_fix'
  tag 'documentable'
  tag legacy: ['SV-83097', 'V-68607']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
