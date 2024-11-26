control 'SV-214196' do
  title 'The Infoblox system must implement cryptographic mechanisms to detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).'
  desc 'Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes. 

Confidentiality is not an objective of DNS, but integrity is. DNSSEC and TSIG/SIG(0) both digitally sign DNS information to authenticate its source and ensure its integrity.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Verify that DNSSEC is enabled by navigating to Data Management >> DNS >> Grid DNS Properties tab.

Toggle Advanced Mode and review the "DNSSEC" tab to verify DNSSEC is enabled.
When complete, click "Cancel" to exit the "Properties" screen.

If DNSSEC is not enabled, this is a finding.'
  desc 'fix', 'Enable DNSSEC is by navigating to Data Management >> DNS >> Grid DNS properties tab.

Toggle Advanced Mode and select the "DNSSEC" tab.
Enable DNSSEC by selecting the check box.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15411r295851_chk'
  tag severity: 'medium'
  tag gid: 'V-214196'
  tag rid: 'SV-214196r612370_rule'
  tag stig_id: 'IDNS-7X-000600'
  tag gtitle: 'SRG-APP-000440-DNS-000065'
  tag fix_id: 'F-15409r295852_fix'
  tag 'documentable'
  tag legacy: ['SV-83077', 'V-68587']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
