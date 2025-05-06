control 'SV-235750' do
  title 'Browser history must be saved.'
  desc 'This setting disables deleting browser history and download history and prevents users from changing this setting.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable deleting browser and download history" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "AllowDeletingBrowserHistory" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable deleting browser and download history" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38969r626446_chk'
  tag severity: 'medium'
  tag gid: 'V-235750'
  tag rid: 'SV-235750r626523_rule'
  tag stig_id: 'EDGE-00-000033'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-38932r626447_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
