control 'SV-214188' do
  title 'A DNS server implementation must provide data origin artifacts for internal name/address resolution queries.'
  desc 'The major threat associated with DNS forged responses or failures is the integrity of the DNS data returned in the response. The principle of DNSSEC is to mitigate this threat by providing data origin authentication, establishing trust in the source. This requirement enables remote clients to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service. 

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS to map between host/service names and network addresses must provide other means to assure the authenticity and integrity of response data. 

In the case of DNS, employ DNSSEC to provide an additional data origin and integrity artifacts along with the authoritative data the system returns in response to DNS name/address resolution queries.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Validate that DNSSEC validation is enabled by navigating to Data Management >> DNS >> Grid DNS properties.

Note: DNSSEC validation is only applicable on a grid member where recursion is active.

Toggle Advanced Mode click on "DNSSEC" tab.
When complete, click "Cancel" to exit the "Properties" screen.

If both "Enable DNSSEC" and "Enable DNSSEC validation" are not enabled, this is a finding.'
  desc 'fix', 'DNSSEC validation is enabled by navigating to Data Management >> DNS >> Grid DNS properties.

Toggle Advanced Mode click on "DNSSEC" tab.
Enable both "Enable DNSSEC" and "Enable DNSSEC validation".
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15403r295827_chk'
  tag severity: 'medium'
  tag gid: 'V-214188'
  tag rid: 'SV-214188r612370_rule'
  tag stig_id: 'IDNS-7X-000490'
  tag gtitle: 'SRG-APP-000420-DNS-000053'
  tag fix_id: 'F-15401r295828_fix'
  tag 'documentable'
  tag legacy: ['SV-83061', 'V-68571']
  tag cci: ['CCI-002463', 'CCI-000366']
  tag nist: ['SC-20 (2)', 'CM-6 b']
end
