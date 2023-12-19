control 'SV-89947' do
  title 'Adobe Acrobat Pro XI PDF file attachments must be blocked.'
  desc 'Acrobat Pro allows for files to be attached to PDF documents. Attachments represent a potential security risk because they can contain malicious content, open other dangerous files, or launch applications.

This feature prevents users from opening or launching file types other than PDF or FDF and disables the menu option to re-enable.'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: iFileAttachmentPerms
Type: REG_DWORD
Value: 1

If the value for iFileAttachmentPerms is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: iFileAttachmentPerms
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75051r3_chk'
  tag severity: 'medium'
  tag gid: 'V-75267'
  tag rid: 'SV-89947r1_rule'
  tag stig_id: 'ADBP-XI-000275'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81883r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
