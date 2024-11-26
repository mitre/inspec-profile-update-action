control 'SV-223285' do
  title 'Document metadata for rights managed Office Open XML files must be protected.'
  desc "This policy setting determines whether metadata is encrypted in Office Open XML files that are protected by Information Rights Management (IRM). If you enable this policy setting, Excel, PowerPoint, and Word encrypt metadata stored in rights-managed Office Open XML files and override any configuration changes on users' computers. 

If you disable this policy setting, Office 2016 applications cannot encrypt metadata in rights-managed Office Open XML files, which can reduce security. If you do not configure this policy setting, when Information Rights Management (IRM) is used to restrict access to an Office Open XML document, any metadata associated with the document is not encrypted."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings "Protect document metadata for rights managed Office Open XML Files" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\security

If the value DRMEncryptProperty is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings "Protect document metadata for rights managed Office Open XML Files" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24958r442074_chk'
  tag severity: 'medium'
  tag gid: 'V-223285'
  tag rid: 'SV-223285r879800_rule'
  tag stig_id: 'O365-CO-000002'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-24946r442075_fix'
  tag 'documentable'
  tag legacy: ['SV-108747', 'V-99643']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
