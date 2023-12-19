control 'SV-33511' do
  title 'Outlook Object Model scripts must be disallowed to run for shared folders.'
  desc 'In Outlook, folders can be associated with custom forms or folder home pages that include scripts that access the Outlook object model. These scripts can add functionality to the folders and items contained within, but dangerous scripts can pose security risks.
By default, Outlook does not allow scripts included in custom forms or folder home pages for shared folders to execute. If this configuration is changed, users can inadvertently run dangerous scripts when using shared folders, which can put their computers or data at risk.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Other -> Advanced “Do not allow Outlook object model scripts to run for shared folders” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value SharedFolderScript is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Other -> Advanced “Do not allow Outlook object model scripts to run for shared folders” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33997r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17676'
  tag rid: 'SV-33511r1_rule'
  tag stig_id: 'DTOO232 - Outlook'
  tag gtitle: 'DTOO232 - OOM scripts for Shared Folders'
  tag fix_id: 'F-29686r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
