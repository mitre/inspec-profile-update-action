control 'SV-213463' do
  title 'Microsoft Defender AV must be configured to prevent user and apps from accessing dangerous websites.'
  desc 'Enable Microsoft Defender Exploit Guard network protection to prevent employees from using any application to access dangerous domains that may host phishing scams, exploit-hosting sites, and other malicious content on the internet.'
  desc 'check', 'This setting is applicable starting with v1709 of Windows 10, it is NA for prior versions.

Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Network Protection >> "Prevent users and apps from accessing dangerous websites" is set to "Enabled” and "Block" is selected in the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection

Criteria: If the value "EnableNetworkProtection" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Windows Defender Exploit Guard >> Network Protection >> "Prevent users and apps from accessing dangerous websites" to "Enabled" and select "Block" in the drop-down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14688r820236_chk'
  tag severity: 'medium'
  tag gid: 'V-213463'
  tag rid: 'SV-213463r823095_rule'
  tag stig_id: 'WNDF-AV-000039'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14686r823094_fix'
  tag 'documentable'
  tag legacy: ['SV-92675', 'V-77979']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
