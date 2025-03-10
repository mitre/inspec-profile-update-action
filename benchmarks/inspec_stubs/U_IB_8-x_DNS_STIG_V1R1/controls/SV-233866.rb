control 'SV-233866' do
  title 'An authoritative name server must be configured to enable DNSSEC resource records.'
  desc "The specification for a digital signature mechanism in the context of the DNS infrastructure is in the Internet Engineering Task Force's (IETF's) DNSSEC standard. In DNSSEC, trust in the public key (for signature verification) of the source is established not by going to a third party or a chain of third parties (as in public key infrastructure [PKI] chaining), but by starting from a trusted zone (such as the root zone) and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. 

The public key of the trusted zone is called the trust anchor. After authenticating the source, the next process DNSSEC calls for is to authenticate the response. DNSSEC mechanisms involve two main processes: sign and serve, and verify signature.

Before a DNSSEC-signed zone can be deployed, a name server must be configured to enable DNSSEC processing."
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable. 

1. Navigate to Data Management >> DNS >> Grid DNS properties. 
2. Toggle Advanced Mode and click on the "DNSSEC" tab.  
3. Validate that DNSSEC is enabled using the check box.  
4. When complete, click "Cancel" to exit the "Properties" screen. 

If "Enable DNSSEC" is not configured, this is a finding.'
  desc 'fix', 'DNSSEC must be enabled prior to zone signing.  

1. Enable by navigating to Data Management >> DNS >> Grid DNS properties. 
2. Toggle Advanced Mode and click on the "DNSSEC" tab. 
3. Enable the "Enable DNSSEC" option.  
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
5. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37051r611118_chk'
  tag severity: 'medium'
  tag gid: 'V-233866'
  tag rid: 'SV-233866r621666_rule'
  tag stig_id: 'IDNS-8X-400008'
  tag gtitle: 'SRG-APP-000516-DNS-000089'
  tag fix_id: 'F-37016r611119_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
