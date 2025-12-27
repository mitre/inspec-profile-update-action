control 'SV-33473' do
  title 'Legacy format signatures must be enabled.'
  desc 'Office applications use the XML–based XMLDSIG format to attach digital signatures to documents, including Office 97-2003 binary documents. XMLDSIG signatures are not recognized by Office 2003 applications or previous versions. If an Office user opens an Excel, PowerPoint, or Word binary document with an XMLDSIG signature attached, the signature will be lost.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Signing “Legacy format signatures” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\signatures

Criteria: If the value XPCompatibleSignatureFormat is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set he policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Signing “Legacy format signatures” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33956r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17749'
  tag rid: 'SV-33473r1_rule'
  tag stig_id: 'DTOO203 - Office System'
  tag gtitle: 'DTOO203 - Legacy Format signatures'
  tag fix_id: 'F-29645r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
