control 'SV-214195' do
  title 'The Infoblox system must be configured to must protect the integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

Confidentiality is not an objective of DNS, but integrity is. DNSSEC and TSIG/SIG(0) both digitally sign DNS information to authenticate its source and ensure its integrity.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Verify that DNSSEC is enabled by navigating to Data Management >> DNS >> Grid DNS properties tab.

Toggle Advanced Mode and review the "DNSSEC" tab to verify DNSSEC is enabled.

When complete, click "Cancel" to exit the "Properties" screen.

If DNSSEC validation is not enabled, this is a finding.'
  desc 'fix', 'Enable that DNSSEC is by navigating to Data Management >> DNS >> Grid DNS properties tab.

Toggle Advanced Mode and select the "DNSSEC" tab.
Enable DNSSEC by selecting the check box.
When complete, click "Save & Exit" to save changes and exit the "Properties" screen.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15410r295848_chk'
  tag severity: 'medium'
  tag gid: 'V-214195'
  tag rid: 'SV-214195r612370_rule'
  tag stig_id: 'IDNS-7X-000590'
  tag gtitle: 'SRG-APP-000439-DNS-000063'
  tag fix_id: 'F-15408r295849_fix'
  tag 'documentable'
  tag legacy: ['SV-83075', 'V-68585']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
