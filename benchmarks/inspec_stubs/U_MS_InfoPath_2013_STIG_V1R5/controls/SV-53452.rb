control 'SV-53452' do
  title 'The InfoPath APTCA Assembly Allowable List must be enforced.'
  desc "InfoPath 2013 forms' business logic can only call into Global Assembly Cache (GAC) assemblies listed in the APTCA Assembly Allowable List. If this configuration is changed, forms can call into any assembly in the GAC where the Allow Partially Trusted Callers Attribute (APTCA) is set. This configuration could allow malicious developers to access assemblies in the GAC not intended to be used by InfoPath forms."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Microsoft InfoPath 2013 (Machine) -> Security "InfoPath APTCA Assembly Allowable List Enforcement" must be set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKLM\\Software\\Policies\\Microsoft\\office\\15.0\\InfoPath\\security

Criteria: If the value APTCA_AllowList is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft InfoPath 2013 (Machine) -> Security "InfoPath APTCA Assembly Allowable List Enforcement" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47667r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26697'
  tag rid: 'SV-53452r1_rule'
  tag stig_id: 'DTOO309'
  tag gtitle: 'DTOO309 - APTCA Assembly Allow List Enforcement'
  tag fix_id: 'F-46378r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
