control 'SV-233907' do
  title 'The Infoblox system must provide additional data origin artifacts along with the authoritative data the system returns in response to external name/address resolution queries.'
  desc "The underlying feature in the major threat associated with DNS query/response (i.e., forged response or response failure) is the integrity of DNS data returned in the response. The security objective is to verify the integrity of each response received. An integral part of integrity verification is to ensure that valid data has originated from the right source. Establishing trust in the source is called data origin authentication. 

The security objectives, and consequently the security services, that are required for securing the DNS query/response transaction are data origin authentication and data integrity verification. 

The specification for a digital signature mechanism in the context of the DNS infrastructure is in the Internet Engineering Task Force's (IETF's) Domain Name System Security Extension (DNSSEC) standard. In DNSSEC, trust in the public key (for signature verification) of the source is established not by going to a third party or a chain of third parties (as in public key infrastructure [PKI] chaining), but by starting from a trusted zone (such as the root zone) and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. The public key of the trusted zone is called the trust anchor."
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

1. Navigate to Data Management >> DNS >> Grid DNS properties. 
2. Toggle Advanced Mode, click on "DNSSEC" tab, and verify that "Enable DNSSEC" is enabled. 
3. Navigate to Data Management >> DNS >> Zones. Verify that the "Signed" column is displayed.
4. Validate that all external authoritative zones are signed by displaying "Yes".
5. When complete, click "Cancel" to exit the "Properties" screen.

If DNSSEC is not enabled and external authoritative zones are not signed, this is a finding.'
  desc 'fix', 'Note: Ensure DNSSEC is configured to meet all other STIG requirements prior to signing a zone to avoid signing with an unapproved configuration.  

1. Navigate to Data Management >> DNS >> Zones tab.  
2. Place a check mark in the box next to the desired external authoritative zone. Using the "DNSSEC" drop-down menu in the toolbar, select "Sign zones". 
3. Acknowledge the informational banner and the service restart banner if prompted.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37092r611241_chk'
  tag severity: 'medium'
  tag gid: 'V-233907'
  tag rid: 'SV-233907r621666_rule'
  tag stig_id: 'IDNS-8X-700002'
  tag gtitle: 'SRG-APP-000213-DNS-000024'
  tag fix_id: 'F-37057r611242_fix'
  tag 'documentable'
  tag cci: ['CCI-001178']
  tag nist: ['SC-20 a']
end
