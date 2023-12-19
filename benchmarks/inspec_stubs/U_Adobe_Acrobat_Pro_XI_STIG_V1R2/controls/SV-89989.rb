control 'SV-89989' do
  title 'Adobe Acrobat Pro XI Webmail must be disabled.'
  desc 'Acrobat Pro XI provides a Webmail capability. This allows users to send PDFs as email attachments using any mail account that supports SMTP/IMAP protocols. In addition to existing desktop email clients, users can now configure these mail accounts by providing User Name, Password, IMAP and SMTP details. The capability allows users to utilize Gmail and Yahoo mail accounts to send PDF files directly from within the Acrobat application. This capability allows the user to by-pass existing email protections provided by DoD email services.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cWebmailProfiles" is not created by default in the Acrobat Pro XI install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cWebmailProfiles

Value Name: bDisableWebmail
Type: REG_DWORD
Value: 1

If the value for bDisableWebmail is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cWebmailProfiles" is not created by default in the Acrobat Pro XI install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cWebmailProfiles

Value Name: bDisableWebmail
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75093r1_chk'
  tag severity: 'low'
  tag gid: 'V-75309'
  tag rid: 'SV-89989r1_rule'
  tag stig_id: 'ADBP-XI-001305'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81925r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
