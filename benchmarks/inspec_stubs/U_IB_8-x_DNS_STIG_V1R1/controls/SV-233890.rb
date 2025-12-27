control 'SV-233890' do
  title 'The Infoblox system must provide the means for authorized individuals to determine the identity of the source of the DNS server-provided information.'
  desc 'Without a means for identifying the individual who produced the information, the information cannot be relied on. Identifying the validity of information may be delayed or deterred.

This requirement provides organizational personnel with the means to identify who produced specific information in the event of an information transfer. DNSSEC uses digital signatures to establish the identity of the producer of particular pieces of information. These signatures can be examined and verified to determine the identity of the producer of the information.'
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
  tag check_id: 'C-37075r611190_chk'
  tag severity: 'medium'
  tag gid: 'V-233890'
  tag rid: 'SV-233890r621666_rule'
  tag stig_id: 'IDNS-8X-400032'
  tag gtitle: 'SRG-APP-000348-DNS-000042'
  tag fix_id: 'F-37040r611191_fix'
  tag 'documentable'
  tag cci: ['CCI-001902', 'CCI-000366']
  tag nist: ['AU-10 (1) (b)', 'CM-6 b']
end
