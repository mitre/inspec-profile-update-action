control 'SV-235770' do
  title 'The collections feature must be disabled.'
  desc 'This setting allows users to access the Collections feature, where they can collect, organize, share, and export content more efficiently and with Office integration.

If this policy is enabled or not configured, users can access and use the Collections feature in Microsoft Edge.

If this policy is disabled, users cannot access and use Collections in Microsoft Edge.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable the Collections feature" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "EdgeCollectionsEnabled" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable the Collections feature" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38989r626506_chk'
  tag severity: 'medium'
  tag gid: 'V-235770'
  tag rid: 'SV-235770r626523_rule'
  tag stig_id: 'EDGE-00-000058'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-38952r626507_fix'
  tag 'documentable'
  tag cci: ['CCI-000393']
  tag nist: ['CM-8 a 2']
end
