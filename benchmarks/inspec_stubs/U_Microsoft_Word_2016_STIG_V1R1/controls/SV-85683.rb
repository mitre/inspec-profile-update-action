control 'SV-85683' do
  title 'Add-ins to Office applications must be signed by a Trusted Publisher.'
  desc "This policy setting controls whether add-ins for this applications must be digitally signed by a trusted publisher. If you enable this policy setting, this application checks the digital signature for each add-in before loading it. If an add-in does not have a digital signature, or if the signature did not come from a trusted publisher, this application disables the add-in and notifies the user. Certificates must be added to the Trusted Publishers list if you require that all add-ins be signed by a trusted publisher. For detail on about obtaining and distributing certificates, see http://go.microsoft.com/fwlink/?LinkId=294922. Office 2016 stores certificates for trusted publishers in the Internet Explorer trusted publisher store. Earlier versions of Microsoft Office stored trusted publisher certificate information (specifically, the certificate thumbprint) in a special Office trusted publisher store.  Office 2016 still reads trusted publisher certificate information from the Office trusted publisher store, but it does not write information to this store. Therefore, if you created a list of trusted publishers in a previous version of Office and you upgrade to Office 2016, your trusted publisher list will still be recognized. However, any trusted publisher certificates that you add to the list will be stored in the Internet Explorer trusted publisher store. For more information about trusted publishers, see the Office Resource Kit. If you disable or do not configure this policy setting, this application does not check the digital signature on application add-ins before opening them. If a dangerous add-in is loaded, it could harm users' computers or compromise data security."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Word Options -> Security -> Trust Center "Require that application add-ins are signed by Trusted Publisher" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\word\\security

Criteria: If the value RequireAddinSig is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Word Options -> Security -> Trust Center "Require that application add-ins are signed by Trusted Publisher" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2016'
  tag check_id: 'C-71487r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71059'
  tag rid: 'SV-85683r1_rule'
  tag stig_id: 'DTOO127'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-77391r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
