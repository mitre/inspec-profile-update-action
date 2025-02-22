control 'SV-33468' do
  title 'Rights managed Office Open XML files must be protected.'
  desc 'When Information Rights Management (IRM) is used to restrict access to an Office Open XML document, any metadata associated with the document is not encrypted. This configuration could allow potentially sensitive information such as the document author and hyperlink references to be exposed to unauthorized people.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Protect document metadata for rights managed Office Open XML Files” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\security

Criteria: If the value DRMEncryptProperty is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Protect document metadata for rights managed Office Open XML Files” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17769'
  tag rid: 'SV-33468r1_rule'
  tag stig_id: 'DTOO187 - Office System'
  tag gtitle: 'DTOO187 - Protect metadata / rights managed docs'
  tag fix_id: 'F-29640r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
