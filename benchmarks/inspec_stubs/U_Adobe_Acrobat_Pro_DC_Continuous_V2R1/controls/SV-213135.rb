control 'SV-213135' do
  title 'Adobe Acrobat Pro DC Continuous Webmail must be disabled.'
  desc 'Acrobat Pro DC provides a Webmail capability. This allows users to send PDFs as email attachments using any mail account that supports SMTP/IMAP protocols. In addition to existing desktop email clients, users can now configure these mail accounts by providing User Name, Password, IMAP and SMTP details. The capability allows users to utilize Gmail and Yahoo mail accounts to send PDF files directly from within the Acrobat application. This capability allows the user to by-pass existing email protections provided by DoD email services.'
  desc 'check', "Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown\\cWebmailProfiles

Value Name: bDisableWebmail
Type: REG_DWORD
Value: 1

If the value for bDisableWebmail is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'WebMail' must be set to 'Disabled'."
  desc 'fix', "Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown\\cWebmailProfiles

Value Name: bDisableWebmail
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'WebMail' to 'Disabled'."
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14372r766557_chk'
  tag severity: 'low'
  tag gid: 'V-213135'
  tag rid: 'SV-213135r766559_rule'
  tag stig_id: 'AADC-CN-001305'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14370r766558_fix'
  tag 'documentable'
  tag legacy: ['SV-94101', 'V-79395']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
