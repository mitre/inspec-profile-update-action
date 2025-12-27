control 'SV-223381' do
  title 'Encrypted macros in PowerPoint Open XML presentations must be scanned.'
  desc 'This policy setting controls whether encrypted macros in Open XML presentations are required to be scanned with anti-virus software before being opened. If you enable this policy setting, you may choose one of these options:

- Scan encrypted macros: Encrypted macros are disabled unless anti-virus software is installed. Encrypted macros are scanned by your anti-virus software when you attempt to open an encrypted presentation that contains macros.
- Scan if anti-virus software available: If anti-virus software is installed, scan the encrypted macros first before allowing them to load. If anti-virus software is not available, allow encrypted macros to load.
- Load macros without scanning: Do not check for anti-virus software and allow macros to be loaded in an encrypted file. If you disable or do not configure this policy setting, the behavior will be similar to the "Scan encrypted macros" option.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security "Scan encrypted macros in PowerPoint Open XML presentations" is set to "Enabled" and "Scan encrypted macros".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\security

If the value PowerPointBypassEncryptedMacroScan does not exist, this is not a finding.

If the value is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security "Scan encrypted macros in PowerPoint Open XML presentations" to "Enabled" and "Scan encrypted macros".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25054r442362_chk'
  tag severity: 'medium'
  tag gid: 'V-223381'
  tag rid: 'SV-223381r879630_rule'
  tag stig_id: 'O365-PT-000005'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25042r442363_fix'
  tag 'documentable'
  tag legacy: ['SV-108937', 'V-99833']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
