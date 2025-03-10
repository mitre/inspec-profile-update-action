control 'SV-53893' do
  title 'Folders in non-default stores, set as folder home pages, must be disallowed.'
  desc "Outlook allows users to designate Web pages as home pages for personal or public folders. When a user clicks on a folder, Outlook displays the home page the user has assigned to it. Although this feature provides the opportunity to create powerful public folder applications, scripts can be included on Web pages that access the Outlook object model, which exposes users to security risks.
By default, Outlook does not allow users to define folder home pages for folders in non-default stores. If this configuration is changed, users can create and access dangerous folder home pages for Outlook data files (.pst) and other non-default stores, which can compromise the security of the users' data."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Other -> Advanced "Do not allow folders in non-default stores to be set as folder home pages" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value NonDefaultStoreScript is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Other -> Advanced "Do not allow folders in non-default stores to be set as folder home pages" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17674'
  tag rid: 'SV-53893r1_rule'
  tag stig_id: 'DTOO230'
  tag gtitle: 'DTOO230 - No fldr home pages / non-default stores'
  tag fix_id: 'F-46800r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
