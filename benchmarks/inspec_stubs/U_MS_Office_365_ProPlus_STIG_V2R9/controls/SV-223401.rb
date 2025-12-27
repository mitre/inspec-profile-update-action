control 'SV-223401' do
  title 'In Word, encrypted macros must be scanned.'
  desc 'This policy setting controls whether encrypted macros in Open XML documents be are required to be scanned with anti-virus software before being opened.

If you enable this policy setting, you may choose one of these options:
- Scan encrypted macros: encrypted macros are disabled unless anti-virus software is installed. Encrypted macros are scanned by your anti-virus software when you attempt to open an encrypted workbook that contains macros.
- Scan if anti-virus software available: if anti-virus software is installed, scan the encrypted macros first before allowing them to load. If anti-virus software is not available, allow encrypted macros to load.
- Load macros without scanning: do not check for anti-virus software and allow macros to be loaded in an encrypted file.

If you disable or do not configure this policy setting, the behavior will be similar to the "Scan encrypted macros" option.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Scan encrypted macros in Word Open XML documents is set to "Enabled" "Scan encrypted macros (default)".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\word\\security

If the value WordBypassEncryptedMacroScan does not exist, this is not a finding. If the value is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Scan encrypted macros in Word Open XML documents to "Enabled" "Scan encrypted macros (default)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25074r442422_chk'
  tag severity: 'medium'
  tag gid: 'V-223401'
  tag rid: 'SV-223401r879630_rule'
  tag stig_id: 'O365-WD-000002'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25062r442423_fix'
  tag 'documentable'
  tag legacy: ['SV-108983', 'V-99879']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
