control 'SV-52768' do
  title 'The configuration for enabling of hyperlinks must be enforced.'
  desc 'Access underlines hyperlinks that appear in tables, queries, forms, and reports. If this configuration is changed, users might click on dangerous hyperlinks without realizing it, which could pose a security risk.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2013-> Application Settings -> Web Options... -> General "Underline Hyperlinks" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\access\\internet

Criteria: If the value DoNotUnderlineHyperlinks is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2013 -> Application Settings -> Web Options... -> General "Underline Hyperlinks" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2013'
  tag check_id: 'C-47097r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17810'
  tag rid: 'SV-52768r1_rule'
  tag stig_id: 'DTOO130'
  tag gtitle: 'DTOO130 - Underline hyperlinks'
  tag fix_id: 'F-45694r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
