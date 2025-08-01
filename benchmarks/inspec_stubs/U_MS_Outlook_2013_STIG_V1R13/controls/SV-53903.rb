control 'SV-53903' do
  title 'Outlook Object Model scripts must be disallowed to run for public folders.'
  desc 'In Outlook, folders can be associated with custom forms or folder home pages that include scripts that access the Outlook object model. These scripts can add functionality to the folders and items contained within, but dangerous scripts can pose security risks.
By default, Outlook allows scripts included in custom forms or folder home pages for public folders to execute. If users inadvertently run dangerous scripts when using public folders, their computers or data could be at risk.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Other -> Advanced "Do not allow Outlook object model scripts to run for public folders" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value PublicFolderScript is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Other -> Advanced "Do not allow Outlook object model scripts to run for public folders" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47924r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17675'
  tag rid: 'SV-53903r1_rule'
  tag stig_id: 'DTOO233'
  tag gtitle: 'DTOO233 - OOM scripts for Public Folders'
  tag fix_id: 'F-46807r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
