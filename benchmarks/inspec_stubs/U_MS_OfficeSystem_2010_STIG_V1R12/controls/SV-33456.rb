control 'SV-33456' do
  title 'Passwords for secured documents must be enforced.'
  desc 'If 2010 Office users add passwords to documents, other users can be prevented from opening the documents. This capability can provide an extra level of protection to documents already protected by access control lists, or provide a means of securing documents not protected by file-level security.
By default, users can add passwords to Excel 2010 workbooks, PowerPoint 2010 presentations, and Word 2010 documents from the Save or Save As dialog box by clicking Tools, clicking General Options, and entering appropriate passwords to open or modify the documents. If this configuration is changed, users will not be able to enter passwords in the General Options dialog box, which means they will not be able to password protect documents.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010-> Security Settings “Disable password to open UI” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\security

Criteria: If the value DisablePasswordUI is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010-> Security Settings “Disable password to open UI” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33939r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17665'
  tag rid: 'SV-33456r1_rule'
  tag stig_id: 'DTOO195 - Office System'
  tag gtitle: 'DTOO195 - Disable Password to Open UI'
  tag fix_id: 'F-29628r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
