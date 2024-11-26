control 'SV-228474' do
  title 'Outlook minimum encryption key length settings must be set.'
  desc 'This policy setting allows you to set the minimum key length for an encrypted e-mail message. If you enable this policy setting, you may set the minimum key length for an encrypted e-mail message.  Outlook will display a warning dialog if the user tries to send a message using an encryption key that is below the minimum encryption key value set. The user can still choose to ignore the warning and send using the encryption key originally chosen. If you disable or do not configure this policy setting, a dialog warning will be shown to the user if the user attempts to send a message using encryption.  The user can still choose to ignore the warning and send using the encryption key originally chosen.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Minimum encryption settings" is set to "Enabled: 168 bits".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value MinEncKey is REG_DWORD = a8 (hex) or 168 (decimal), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Minimum encryption settings" to "Enabled: 168 bits".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30707r497744_chk'
  tag severity: 'medium'
  tag gid: 'V-228474'
  tag rid: 'SV-228474r508021_rule'
  tag stig_id: 'DTOO316'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-30692r497745_fix'
  tag 'documentable'
  tag legacy: ['SV-85897', 'V-71273']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
