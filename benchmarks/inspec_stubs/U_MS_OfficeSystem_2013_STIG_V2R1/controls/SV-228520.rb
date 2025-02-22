control 'SV-228520' do
  title 'Legacy format signatures must be enabled.'
  desc 'Office applications use the XML-based XMLDSIG format to attach digital signatures to documents, including Office 97-2003 binary documents. XMLDSIG signatures are not recognized by Office 2003 applications or previous versions. If an Office user opens an Excel, PowerPoint, or Word binary document with an XMLDSIG signature attached, the signature will be lost.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Signing "Legacy format signatures" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\signatures

If the value 'EnableCreationOfWeakXPSignatures' is REG_DWORD = 1, this is not a finding.

Fix Text: Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Signing "Legacy format signatures" to "Enabled".)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Signing "Legacy format signatures" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30753r498838_chk'
  tag severity: 'medium'
  tag gid: 'V-228520'
  tag rid: 'SV-228520r508020_rule'
  tag stig_id: 'DTOO203'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30738r498839_fix'
  tag 'documentable'
  tag legacy: ['V-17749', 'SV-52751']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
