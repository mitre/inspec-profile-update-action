control 'SV-48250' do
  title 'Indexing of mail items in Exchange folders when Outlook is running in uncached mode must be turned off.'
  desc 'Indexing of encrypted items may expose sensitive data.  This setting prevents mail items in a Microsoft Exchange folder from being indexed when Outlook is running in uncached mode.'
  desc 'check', 'If Outlook is not installed on the system, this is NA.
If Outlook is installed on the system and the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\

Value Name:  PreventIndexingUncachedExchangeFolders

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'If Outlook is not installed on the system, this is NA.
If Outlook is installed on the system, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Search -> "Enable indexing uncached Exchange folders" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-57985r1_chk'
  tag severity: 'low'
  tag gid: 'V-15712'
  tag rid: 'SV-48250r3_rule'
  tag stig_id: 'WN08-CC-000108'
  tag gtitle: 'Search – Exchange Folder Indexing'
  tag fix_id: 'F-62309r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
