control 'SV-235770' do
  title 'The collections feature must be disabled.'
  desc 'This setting allows users to access the Collections feature, where they can collect, organize, share, and export content more efficiently and with Office integration.

If this policy is enabled or not configured, users can access and use the Collections feature in Microsoft Edge.

If this policy is disabled, users cannot access and use Collections in Microsoft Edge.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable the Collections feature" must be set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "EdgeCollectionsEnabled" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable the Collections feature" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38989r766878_chk'
  tag severity: 'medium'
  tag gid: 'V-235770'
  tag rid: 'SV-235770r766880_rule'
  tag stig_id: 'EDGE-00-000058'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-38952r766879_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
