control 'SV-214182' do
  title 'The Infoblox system must be configured to provide the means for authorized individuals to determine the identity of the source of the DNS server-provided information.'
  desc 'Without a means for identifying the individual that produced the information, the information cannot be relied upon. Identifying the validity of information may be delayed or deterred.

This requirement provides organizational personnel with the means to identify who produced specific information in the event of an information transfer. DNSSEC and TSIG/SIG(0) both use digital signatures to establish the identity of the producer of particular pieces of information. These signatures can be examined and verified to determine the identity of the producer of the information.'
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
  tag check_id: 'C-15397r295809_chk'
  tag severity: 'medium'
  tag gid: 'V-214182'
  tag rid: 'SV-214182r612370_rule'
  tag stig_id: 'IDNS-7X-000400'
  tag gtitle: 'SRG-APP-000348-DNS-000042'
  tag fix_id: 'F-15395r295810_fix'
  tag 'documentable'
  tag legacy: ['SV-83049', 'V-68559']
  tag cci: ['CCI-001902', 'CCI-000366']
  tag nist: ['AU-10 (1) (b)', 'CM-6 b']
end
