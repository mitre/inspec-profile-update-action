control 'SV-228550' do
  title 'Passwords for secured documents must be enforced.'
  desc 'If 2013 Office users add passwords to documents, other users can be prevented from opening the documents. This capability can provide an extra level of protection to documents already protected by access control lists, or provide a means of securing documents not protected by file-level security.
By default, users can add passwords to Excel 2013 workbooks, PowerPoint 2013 presentations, and Word 2013 documents from the Save or Save As dialog box by clicking Tools, clicking General Options, and entering appropriate passwords to open or modify the documents. If this configuration is changed, the General Options dialog box for saving with a password will not be available for the user to password-protect their documents.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Disable password to open UI" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 
HKCU\Software\Policies\Microsoft\Office\15.0\common\security

If the value 'DisablePasswordUI' is REG_DWORD = 0, this is not a finding.

Fix Text: Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Disable password to open UI" to "Disabled".)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "Disable password to open UI" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30783r498928_chk'
  tag severity: 'medium'
  tag gid: 'V-228550'
  tag rid: 'SV-228550r508020_rule'
  tag stig_id: 'DTOO195'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-30768r498929_fix'
  tag 'documentable'
  tag legacy: ['SV-52744', 'V-17665']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
