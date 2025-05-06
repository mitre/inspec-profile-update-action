control 'SV-233889' do
  title 'An Infoblox DNS server must strongly bind the identity of the DNS server with the DNS information using DNSSEC.'
  desc 'Weakly bound credentials can be modified without invalidating the credential; therefore, non-repudiation can be violated.

This requirement supports audit requirements that provide organizational personnel with the means to identify who produced specific information in the event of an information transfer. Organizations and/or data owners determine and approve the strength of the binding between the information producer and the information based on the security category of the information and relevant risk factors.

DNSSEC uses digital signatures to establish the identity of the producer of particular pieces of information.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable. 

Validate that DNSSEC validation is enabled:  

1. Navigate to Data Management >> DNS >> Grid DNS properties.
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
  tag check_id: 'C-37074r611187_chk'
  tag severity: 'medium'
  tag gid: 'V-233889'
  tag rid: 'SV-233889r621666_rule'
  tag stig_id: 'IDNS-8X-400031'
  tag gtitle: 'SRG-APP-000347-DNS-000041'
  tag fix_id: 'F-37039r611188_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001901']
  tag nist: ['CM-6 b', 'AU-10 (1) (a)']
end
