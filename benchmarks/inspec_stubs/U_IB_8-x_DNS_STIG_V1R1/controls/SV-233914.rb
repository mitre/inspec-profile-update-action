control 'SV-233914' do
  title 'The Infoblox DNS server must request data integrity verification on the name/address resolution responses the system receives from authoritative sources.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed that would result in query failure or denial of service. Data integrity verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching DNS servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations."
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
  tag check_id: 'C-37099r611262_chk'
  tag severity: 'medium'
  tag gid: 'V-233914'
  tag rid: 'SV-233914r621666_rule'
  tag stig_id: 'IDNS-8X-700009'
  tag gtitle: 'SRG-APP-000424-DNS-000057'
  tag fix_id: 'F-37064r611263_fix'
  tag 'documentable'
  tag cci: ['CCI-002466']
  tag nist: ['SC-21']
end
