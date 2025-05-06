control 'SV-85291' do
  title 'The scanning of encrypted macros in open XML documents must be enforced.'
  desc 'This policy setting controls whether encrypted macros in Open XML presentations are required to be scanned with anti-virus software before being opened. If you enable this policy setting, you may choose one of these options:- Scan encrypted macros: encrypted macros are disabled unless anti-virus software is installed.  Encrypted macros are scanned by your anti-virus software when you attempt to open an encrypted presentation that contains macros.- Scan if anti-virus software available: if anti-virus software is installed, scan the encrypted macros first before allowing them to load.  If anti-virus software is not available, allow encrypted macros to load.- Load macros without scanning: do not check for anti-virus software and allow macros to be loaded in an encrypted file.  If you disable or do not configure this policy setting, the behavior will be similar to the "Scan encrypted macros" option.'
  desc 'check', %q(Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security "Scan encrypted macros in PowerPoint Open XML presentations" is set to "Disabled".  The option 'Enabled: Scan encrypted macros (default)' is also an acceptable value. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\security

Criteria: If the value PowerPointBypassEncryptedMacroScan does not exist, this not a finding.  If the value is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security "Scan encrypted macros in PowerPoint Open XML presentations" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2016'
  tag check_id: 'C-71069r4_chk'
  tag severity: 'medium'
  tag gid: 'V-70669'
  tag rid: 'SV-85291r1_rule'
  tag stig_id: 'DTOO142'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-76913r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
