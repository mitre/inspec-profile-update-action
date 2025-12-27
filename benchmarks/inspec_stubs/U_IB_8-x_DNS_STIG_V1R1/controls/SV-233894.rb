control 'SV-233894' do
  title 'The Infoblox DNS server must provide data integrity protection artifacts for internal name/address resolution queries.'
  desc 'The major threat associated with DNS forged responses or failures is the integrity of the DNS data returned in the response. The principle of DNSSEC is to mitigate this threat by providing data origin authentication, establishing trust in the source. This requirement enables remote clients to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service. 

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS to map between host/service names and network addresses must provide other means to ensure the authenticity and integrity of response data. 

In the case of DNS, employ DNSSEC to provide an additional data origin and integrity artifacts along with the authoritative data the system returns in response to DNS name/address resolution queries.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.   

1. Validate that DNSSEC validation is enabled by navigating to Data Management >> DNS >> Grid DNS properties.
2. Toggle Advanced Mode and click on the "DNSSEC" tab.  
3. Verify that both "Enable DNSSEC" and "Enable DNSSEC validation" are enabled.  
4. When complete, click "Cancel" to exit the "Properties" screen.   

If both "Enable DNSSEC" and "Enable DNSSEC validation" are not enabled, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Grid DNS properties.
2. Toggle Advanced Mode and click on the "DNSSEC" tab. 
3. Enable both "Enable DNSSEC" and "Enable DNSSEC validation". 
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
5. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37079r611202_chk'
  tag severity: 'medium'
  tag gid: 'V-233894'
  tag rid: 'SV-233894r621666_rule'
  tag stig_id: 'IDNS-8X-400036'
  tag gtitle: 'SRG-APP-000421-DNS-000054'
  tag fix_id: 'F-37044r611203_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002464']
  tag nist: ['CM-6 b', 'SC-20 (2)']
end
