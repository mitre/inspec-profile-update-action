control 'SV-235732' do
  title 'Importing of cookies must be disabled.'
  desc 'Allows users to import cookies from another browser into Microsoft Edge.

If this policy is disabled, cookies are not imported on first run.

If this policy is not configured, cookies are imported on first run.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of cookies" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportCookies" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of cookies" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38951r626392_chk'
  tag severity: 'medium'
  tag gid: 'V-235732'
  tag rid: 'SV-235732r626523_rule'
  tag stig_id: 'EDGE-00-000015'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38914r626393_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
