control 'SV-213119' do
  title 'Adobe Acrobat Pro DC Continuous PDF file attachments must be blocked.'
  desc 'Acrobat Pro allows for files to be attached to PDF documents. Attachments represent a potential security risk because they can contain malicious content, open other dangerous files, or launch applications.This feature prevents users from opening or launching file types other than PDF or FDF and disables the menu option to re-enable.'
  desc 'check', "Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: iFileAttachmentPerms
Type: REG_DWORD
Value: 1

If the value for iFileAttachmentPerms is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > Trust Manager > In the 'PDF File Attachments' section > Verify  'Allow opening of non-PDF file attachments with external applications' checkbox is unchecked and greyed out (locked).  If the box is checked and not greyed out (locked), this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Trust Manager > 'Allow opening of non-PDF file attachments with external applications' must be set to 'Disabled'."
  desc 'fix', "Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: iFileAttachmentPerms
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Trust Manager > 'Allow opening of non-PDF file attachments with external applications' to 'Disabled'."
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14356r766515_chk'
  tag severity: 'medium'
  tag gid: 'V-213119'
  tag rid: 'SV-213119r766517_rule'
  tag stig_id: 'AADC-CN-000275'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14354r766516_fix'
  tag 'documentable'
  tag legacy: ['SV-94069', 'V-79363']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
