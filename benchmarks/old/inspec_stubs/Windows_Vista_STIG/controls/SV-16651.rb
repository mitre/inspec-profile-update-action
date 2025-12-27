control 'SV-16651' do
  title 'Indexing of mail items in Exchange folders when Outlook is running in uncached mode must be turned off.'
  desc 'Indexing of encrypted items may expose sensitive data.  This setting prevents mail items in a Microsoft Exchange folder from being indexed when Outlook is running in uncached mode.'
  desc 'fix', 'If Outlook is not installed on the system, this is NA.
If Outlook is installed on the system, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Search -> "Enable indexing uncached Exchange folders" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15712'
  tag rid: 'SV-16651r2_rule'
  tag gtitle: 'Search – Exchange Folder Indexing'
  tag fix_id: 'F-62305r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
