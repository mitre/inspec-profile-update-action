control 'SV-94101' do
  title 'Adobe Acrobat Pro DC Continuous Webmail must be disabled.'
  desc 'Acrobat Pro DC provides a Webmail capability. This allows users to send PDFs as email attachments using any mail account that supports SMTP/IMAP protocols. In addition to existing desktop email clients, users can now configure these mail accounts by providing User Name, Password, IMAP and SMTP details. The capability allows users to utilize Gmail and Yahoo mail accounts to send PDF files directly from within the Acrobat application. This capability allows the user to by-pass existing email protections provided by DoD email services.'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cWebmailProfiles

Value Name: bDisableWebmail
Type: REG_DWORD
Value: 1

If the value for bDisableWebmail is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'WebMail' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cWebmailProfiles

Value Name: bDisableWebmail
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'WebMail' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro DC Continuous'
  tag check_id: 'C-79009r3_chk'
  tag severity: 'low'
  tag gid: 'V-79395'
  tag rid: 'SV-94101r1_rule'
  tag stig_id: 'AADC-CN-001305'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-86167r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
