control 'SV-233924' do
  title 'The Infoblox DNS server must implement cryptographic mechanisms to detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).'
  desc 'Encrypting information for transmission protects it from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes. 

Confidentiality is not an objective of DNS, but integrity is. DNSSEC digitally signs DNS information to authenticate its source and ensure its integrity.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

1. Verify that DNSSEC is enabled by navigating to Data Management >> DNS >> Grid DNS properties tab. 
2. Toggle Advanced Mode and review the "DNSSEC" tab to verify that DNSSEC is enabled. 
3. When complete, click "Cancel" to exit the "Properties" screen. 

If DNSSEC validation is not enabled, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Grid DNS properties tab. 
2. Toggle Advanced Mode and select the "DNSSEC" tab.  
3. Enable DNSSEC by selecting the check box.  
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.  
5. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37109r611292_chk'
  tag severity: 'medium'
  tag gid: 'V-233924'
  tag rid: 'SV-233924r621666_rule'
  tag stig_id: 'IDNS-8X-700019'
  tag gtitle: 'SRG-APP-000440-DNS-000065'
  tag fix_id: 'F-37074r611293_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
