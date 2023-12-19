control 'SV-214168' do
  title 'The Infoblox system must be configured to provide additional data origin artifacts along with the authoritative data the system returns in response to external name/address resolution queries.'
  desc 'The underlying feature in the major threat associated with DNS query/response (i.e., forged response or response failure) is the integrity of DNS data returned in the response. The security objective is to verify the integrity of each response received. An integral part of integrity verification is to ensure that valid data has originated from the right source. Establishing trust in the source is called data origin authentication. 

The security objectives—and consequently the security services—that are required for securing the DNS query/response transaction are data origin authentication and data integrity verification.

The specification for a digital signature mechanism in the context of the DNS infrastructure is in IETF’s DNSSEC standard. In DNSSEC, trust in the public key (for signature verification) of the source is established not by going to a third party or a chain of third parties (as in public key infrastructure [PKI] chaining), but by starting from a trusted zone (such as the root zone) and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. The public key of the trusted zone is called the trust anchor.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Navigate to Data Management >> DNS >> Grid DNS properties.

Toggle Advanced Mode click on "DNSSEC" tab, verify "Enable DNSSEC" is enabled.

Navigate to Data Management >> DNS >> Zones.

Verify that the "Signed" column is displayed.
Validate that all external authoritative zones are signed by displaying "Yes".
When complete, click "Cancel" to exit the "Properties" screen.

If DNSSEC is not enabled, and external authoritative zones are not signed, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Zones tab.

Place a check mark in the box next to the desired external authoritative zone. Using the "DNSSEC" drop-down menu in the toolbar, select "Sign zones". Acknowledge the informational banner and the service restart banner if prompted.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15383r295770_chk'
  tag severity: 'medium'
  tag gid: 'V-214168'
  tag rid: 'SV-214168r612370_rule'
  tag stig_id: 'IDNS-7X-000210'
  tag gtitle: 'SRG-APP-000213-DNS-000024'
  tag fix_id: 'F-15381r295771_fix'
  tag 'documentable'
  tag legacy: ['V-68531', 'SV-83021']
  tag cci: ['CCI-001178']
  tag nist: ['SC-20 a']
end
