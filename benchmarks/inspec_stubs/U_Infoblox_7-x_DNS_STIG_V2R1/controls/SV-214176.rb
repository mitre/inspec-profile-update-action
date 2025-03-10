control 'SV-214176' do
  title 'Infoblox DNS servers must be configured to protect the authenticity of communications sessions for queries.'
  desc 'The underlying feature in the major threat associated with DNS query/response (i.e., forged response or response failure) is the integrity of DNS data returned in the response. An integral part of integrity verification is to ensure that valid data has originated from the right source. DNSSEC is required for securing the DNS query/response transaction by providing data origin authentication and data integrity verification through signature verification and the chain of trust.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Validate that DNSSEC validation is enabled by navigating to Data Management >> DNS >> Grid DNS properties, toggle Advanced Mode click on "DNSSEC" tab. 

When complete, click "Cancel" to exit the "Properties" screen.

Note: DNSSEC validation is only applicable on a grid member where recursion is active.

If both "Enable DNSSEC" and "Enable DNSSEC validation" are not enabled, this is a finding.'
  desc 'fix', 'DNSSEC validation is enabled by navigating to Data Management >> DNS >> Grid DNS properties, toggle Advanced Mode click on "DNSSEC" tab.

Enable both "Enable DNSSEC" and "Enable DNSSEC validation". 
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15391r295791_chk'
  tag severity: 'medium'
  tag gid: 'V-214176'
  tag rid: 'SV-214176r612370_rule'
  tag stig_id: 'IDNS-7X-000290'
  tag gtitle: 'SRG-APP-000219-DNS-000030'
  tag fix_id: 'F-15389r295792_fix'
  tag 'documentable'
  tag legacy: ['V-68701', 'SV-83191']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
