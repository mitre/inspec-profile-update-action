control 'SV-55995' do
  title 'Information shared with Bing in Search must be configured to the most restrictive setting.'
  desc 'Various levels of information can be shared with Bing in Search, to include user information and location.  Configuring this setting prevents users from selecting the level of information shared and enables the most restrictive selection.'
  desc 'check', 'Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\

Value Name: ConnectedSearchPrivacy

Value Type: REG_DWORD
Value: 3'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Search >> "Set what information is shared in Search" to "Enabled" with "Anonymous" selected in "Type of Information".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66271r1_chk'
  tag severity: 'medium'
  tag gid: 'V-43242'
  tag rid: 'SV-55995r3_rule'
  tag stig_id: 'WN08-CC-000142'
  tag gtitle: 'WINCC-000142'
  tag fix_id: 'F-71659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
