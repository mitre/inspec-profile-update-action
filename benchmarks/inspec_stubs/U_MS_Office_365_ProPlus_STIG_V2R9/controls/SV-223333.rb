control 'SV-223333' do
  title 'Scan of encrypted macros in Excel Open XML workbooks must be enabled.'
  desc 'This policy setting controls whether encrypted macros in Open XML workbooks be are required to be scanned with anti-virus software before being opened.

If you enable this policy setting, you may choose one of these options:
- Scan encrypted macros: encrypted macros are disabled unless anti-virus software is installed. Encrypted macros are scanned by your anti-virus software when you attempt to open an encrypted workbook that contains macros.
- Scan if anti-virus software available: if anti-virus software is installed, scan the encrypted macros first before allowing them to load. If anti-virus software is not available, allow encrypted macros to load.
- Load macros without scanning: do not check for anti-virus software and allow macros to be loaded in an encrypted file.

If you disable or do not configure this policy setting, the behavior will be similar to the "Scan encrypted macros" option.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Scan encrypted macros in Excel Open XML workbooks is set to "Scan encrypted macros (default)".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security

If the value excelbypassencryptedmacroscan does not exist, this is not a finding.

If the value for excelbypassencryptedmacroscan is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Scan encrypted macros in Excel Open XML workbooks to "Scan encrypted macros (default)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25006r904326_chk'
  tag severity: 'medium'
  tag gid: 'V-223333'
  tag rid: 'SV-223333r904327_rule'
  tag stig_id: 'O365-EX-000024'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24994r442219_fix'
  tag 'documentable'
  tag legacy: ['SV-108845', 'V-99741']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
