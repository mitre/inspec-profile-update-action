control 'SV-85563' do
  title 'The configuration for enabling of hyperlinks must be enforced.'
  desc "This policy setting controls whether hyperlinks in Access tables, queries, forms, and reports are underlined. If you enable this policy setting, Access underlines all hyperlinks in tables, queries, forms, and reports when they are created, overriding any configuration changes on the users' computers. If you disable this policy setting, Access does not underline hyperlinks in tables, queries, forms and reports. If you do not configure this policy setting, Access underlines hyperlinks that appear in tables, queries, forms, and reports. Enabling this policy setting enforces the default configuration in Access, and is therefore unlikely to cause a significant usability issue for most users. If this configuration is changed, users might click on dangerous hyperlinks without realizing it, which could pose a security risk."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2016-> Application Settings -> Web Options... -> General "Underline Hyperlinks" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\access\\internet

Criteria: If the value DoNotUnderlineHyperlinks is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2016 -> Application Settings -> Web Options... -> General "Underline Hyperlinks" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2016'
  tag check_id: 'C-71367r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70939'
  tag rid: 'SV-85563r1_rule'
  tag stig_id: 'DTOO130'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-77271r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
