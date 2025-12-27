control 'SV-235740' do
  title 'Importing of shortcuts must be disabled.'
  desc 'Allows users to import Shortcuts from another browser into Microsoft Edge.

If this policy is disabled, Shortcuts are not imported on first run.

If this policy is not configured, Shortcuts are imported on first run.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of shortcuts" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportShortcuts" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of shortcuts" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38959r626416_chk'
  tag severity: 'medium'
  tag gid: 'V-235740'
  tag rid: 'SV-235740r626523_rule'
  tag stig_id: 'EDGE-00-000023'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38922r626417_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
