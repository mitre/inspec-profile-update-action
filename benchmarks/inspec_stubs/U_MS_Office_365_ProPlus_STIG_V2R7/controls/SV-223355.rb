control 'SV-223355' do
  title 'The Publish to Global Address List (GAL) button must be disabled in Outlook.'
  desc 'This policy setting controls whether Outlook users can publish e-mail certificates to the Global Address List (GAL). 

If you enable this policy setting, the "Publish to GAL" button does not display in the "E-mail Security" section of the Trust Center. 

If you disable or do not configure this policy setting, Outlook users can publish their e-mail certificates to the GAL through the "E-mail Security" section of the Trust Center.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Cryptography >> Do not display 'Publish to GAL' button is set to "Enabled".

Use the Windows Registry to navigate to the following key:

HKCU\software\policies\microsoft\office\16.0\outlook\security

If the value for publishtogaldisabled is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Cryptography >> Do not display 'Publish to GAL' button to "Enabled".)
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25028r811488_chk'
  tag severity: 'medium'
  tag gid: 'V-223355'
  tag rid: 'SV-223355r811489_rule'
  tag stig_id: 'O365-OU-000010'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-25016r442285_fix'
  tag 'documentable'
  tag legacy: ['SV-108889', 'V-99785']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
