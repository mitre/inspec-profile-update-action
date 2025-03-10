control 'SV-238026' do
  title 'Rights managed Office Open XML files must be protected.'
  desc "This policy setting determines whether metadata is encrypted in Office Open XML files that are protected by Information Rights Management (IRM). If you enable this policy setting, Excel, PowerPoint, and Word encrypt metadata stored in rights-managed Office Open XML files and override any configuration changes on users' computers. If you disable this policy setting, Office 2016 applications cannot encrypt metadata in rights-managed Office Open XML files, which can reduce security. If you do not configure this policy setting, when Information Rights Management (IRM) is used to restrict access to an Office Open XML document, any metadata associated with the document is not encrypted."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Protect document metadata for rights managed Office Open XML Files" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\security

Criteria: If the value DRMEncryptProperty is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Protect document metadata for rights managed Office Open XML Files" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41236r650643_chk'
  tag severity: 'medium'
  tag gid: 'V-238026'
  tag rid: 'SV-238026r650645_rule'
  tag stig_id: 'DTOO187'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-41195r650644_fix'
  tag 'documentable'
  tag legacy: ['SV-85485', 'V-70861']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
