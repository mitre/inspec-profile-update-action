control 'SV-223356' do
  title 'The minimum encryption key length in Outlook must be at least 168.'
  desc 'This policy setting allows you to set the minimum key length for an encrypted e-mail message.

If you enable this policy setting, you may set the minimum key length for an encrypted e-mail message. Outlook will display a warning dialog if the user tries to send a message using an encryption key that is below the minimum encryption key value set. The user can still choose to ignore the warning and send using the encryption key originally chosen.

If you disable or do not configure this policy setting, a dialog warning will be shown to the user if the user attempts to send a message using encryption. The user can still choose to ignore the warning and send using the encryption key originally chosen.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Cryptography >> Minimum encryption settings is set to "Enabled" and a Minimum key size (in bits) of "168" or above.

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for minenckey is set to 168 or above, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Cryptography >> Minimum encryption settings to "Enabled"and a Minimum key size (in bits) of "168" or above.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25029r442287_chk'
  tag severity: 'medium'
  tag gid: 'V-223356'
  tag rid: 'SV-223356r879901_rule'
  tag stig_id: 'O365-OU-000011'
  tag gtitle: 'SRG-APP-000630'
  tag fix_id: 'F-25017r442288_fix'
  tag 'documentable'
  tag legacy: ['SV-108891', 'V-99787']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
