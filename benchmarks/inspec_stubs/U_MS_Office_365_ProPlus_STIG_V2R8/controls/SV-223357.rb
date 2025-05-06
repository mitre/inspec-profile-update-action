control 'SV-223357' do
  title 'The warning about invalid digital signatures must be enabled to warn Outlook users.'
  desc 'This policy setting controls how Outlook warns users about messages with invalid digital signatures.

If you enable this policy setting, you can choose from three options for controlling how Outlook users are warned about invalid signatures:
- Let user decide if they want to be warned. This option enforces the default configuration.
- Always warn about invalid signatures.
- Never warn about invalid signatures.

If you disable or do not configure this policy setting, if users open e-mail messages that include invalid digital signatures, Outlook displays a warning dialog. Users can decide whether they want to be warned about invalid signatures in the future.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Cryptography >> Signature Warning is set to "Enabled" "Always warn about invalid signatures".

Use the Windows Registry to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for warnaboutinvalid is set to REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Cryptography >> Signature Warning to "Enabled" "Always warn about invalid signatures".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25030r442290_chk'
  tag severity: 'medium'
  tag gid: 'V-223357'
  tag rid: 'SV-223357r879628_rule'
  tag stig_id: 'O365-OU-000012'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25018r442291_fix'
  tag 'documentable'
  tag legacy: ['SV-108893', 'V-99789']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
