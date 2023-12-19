control 'SV-233923' do
  title 'The Infoblox DNS server must protect the integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

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
  tag check_id: 'C-37108r611289_chk'
  tag severity: 'medium'
  tag gid: 'V-233923'
  tag rid: 'SV-233923r621666_rule'
  tag stig_id: 'IDNS-8X-700018'
  tag gtitle: 'SRG-APP-000439-DNS-000063'
  tag fix_id: 'F-37073r611290_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
