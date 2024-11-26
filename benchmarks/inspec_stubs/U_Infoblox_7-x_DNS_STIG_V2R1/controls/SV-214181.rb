control 'SV-214181' do
  title 'An Infoblox DNS server must strongly bind the identity of the DNS server with the DNS information using DNSSEC.'
  desc 'Weakly bound credentials can be modified without invalidating the credential; therefore, non-repudiation can be violated.

This requirement supports audit requirements that provide organizational personnel with the means to identify who produced specific information in the event of an information transfer. Organizations and/or data owners determine and approve the strength of the binding between the information producer and the information based on the security category of the information and relevant risk factors.

DNSSEC uses digital signatures to verify the identity of the producer of particular pieces of information.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Validate that DNSSEC validation is enabled by navigating to Data Management >> DNS >> Grid DNS properties, toggle Advanced Mode click on "DNSSEC" tab.

Note: DNSSEC validation is only applicable on a grid member where recursion is active.

When complete, click "Cancel" to exit the "Properties" screen.

If both "Enable DNSSEC" and "Enable DNSSEC validation" are not enabled, this is a finding.'
  desc 'fix', 'DNSSEC validation is enabled by navigating to Data Management >> DNS >> Grid DNS properties, toggle Advanced Mode click on "DNSSEC" tab.

Enable both "Enable DNSSEC" and "Enable DNSSEC validation".
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15396r295806_chk'
  tag severity: 'medium'
  tag gid: 'V-214181'
  tag rid: 'SV-214181r612370_rule'
  tag stig_id: 'IDNS-7X-000390'
  tag gtitle: 'SRG-APP-000347-DNS-000041'
  tag fix_id: 'F-15394r295807_fix'
  tag 'documentable'
  tag legacy: ['SV-83047', 'V-68557']
  tag cci: ['CCI-000366', 'CCI-001901']
  tag nist: ['CM-6 b', 'AU-10 (1) (a)']
end
