control 'SV-33428' do
  title 'Configuration for enabling of hyperlinks must be enforced.'
  desc 'Access underlines hyperlinks that appear in tables, queries, forms, and reports. If this configuration is changed, users might click on dangerous hyperlinks without realizing it, which could pose a security risk'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010-> Application Settings -> Web Options... -> General “Underline Hyperlinks” must be “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\access\\internet

Criteria: If the value DoNotUnderlineHyperlinks is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010 -> Application Settings -> Web Options... -> General “Underline Hyperlinks” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2010'
  tag check_id: 'C-33911r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17810'
  tag rid: 'SV-33428r1_rule'
  tag stig_id: 'DTOO130 - Access'
  tag gtitle: 'DTOO130 - Underline hyperlinks'
  tag fix_id: 'F-29600r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
