control 'SV-233919' do
  title 'Infoblox DNS servers must protect the authenticity of communications sessions for queries.'
  desc 'The underlying feature in the major threat associated with DNS query/response (i.e., forged response or response failure) is the integrity of DNS data returned in the response. An integral part of integrity verification is to ensure that valid data has originated from the right source. DNSSEC is required for securing the DNS query/response transaction by providing data origin authentication and data integrity verification through signature verification and the chain of trust.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

1. Navigate to Data Management >> DNS >> Grid DNS properties.
2. Toggle Advanced Mode and click on "DNSSEC" tab. 
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
  tag check_id: 'C-37104r611277_chk'
  tag severity: 'medium'
  tag gid: 'V-233919'
  tag rid: 'SV-233919r621666_rule'
  tag stig_id: 'IDNS-8X-700014'
  tag gtitle: 'SRG-APP-000219-DNS-000030'
  tag fix_id: 'F-37069r611278_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
